// Copyright 2015 CNI authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/rpc"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"sync"
	"syscall"
	"time"

	"github.com/coreos/go-systemd/v22/activation"

	"github.com/containernetworking/cni/pkg/skel"
	current "github.com/containernetworking/cni/pkg/types/100"
)

var errNoMoreTries = errors.New("no more tries")

type DHCP struct {
	mux                 sync.Mutex
	leases              map[string]*DHCPLease
	hostNetnsPrefix     string
	clientTimeout       time.Duration
	clientResendMax     time.Duration
	clientResendTimeout time.Duration
	broadcast           bool
}

func newDHCP(clientTimeout, clientResendMax time.Duration, resendTimeout time.Duration) *DHCP {
	return &DHCP{
		leases:              make(map[string]*DHCPLease),
		clientTimeout:       clientTimeout,
		clientResendMax:     clientResendMax,
		clientResendTimeout: resendTimeout,
	}
}

// TODO: current client ID is too long. At least the container ID should not be used directly.
// A separate issue is necessary to ensure no breaking change is affecting other users.
func generateClientID(containerID string, netName string, ifName string) string {
	clientID := containerID + "/" + netName + "/" + ifName
	// defined in RFC 2132, length size can not be larger than 1 octet. So we truncate 254 to make everyone happy.
	if len(clientID) > 254 {
		clientID = clientID[0:254]
	}
	return clientID
}

// Allocate acquires an IP from a DHCP server for a specified container.
// The acquired lease will be maintained until Release() is called.
func (d *DHCP) Allocate(args *skel.CmdArgs, result *current.Result) error {
	conf := NetConf{}
	if err := json.Unmarshal(args.StdinData, &conf); err != nil {
		return fmt.Errorf("error parsing netconf: %v", err)
	}

	opts, err := prepareOptions(args.Args, conf.IPAM.ProvideOptions, conf.IPAM.RequestOptions)
	if err != nil {
		return err
	}

	clientID := generateClientID(args.ContainerID, conf.Name, args.IfName)

	// If we already have an active lease for this clientID, do not create
	// another one
	l := d.getLease(clientID)
	if l != nil {
		l.Check()
	} else {
		hostNetns := d.hostNetnsPrefix + args.Netns
		l, err = AcquireLease(clientID, hostNetns, args.IfName,
			opts,
			d.clientTimeout, d.clientResendMax, d.clientResendTimeout, d.broadcast)
		if err != nil {
			return err
		}
	}

	ipn, err := l.IPNet()
	if err != nil {
		l.Stop()
		return err
	}

	d.setLease(clientID, l)

	result.IPs = []*current.IPConfig{{
		Address: *ipn,
		Gateway: l.Gateway(),
	}}
	result.Routes = l.Routes()
	if conf.IPAM.Priority != 0 {
		for _, r := range result.Routes {
			r.Priority = conf.IPAM.Priority
		}
	}

	return nil
}

// Release stops maintenance of the lease acquired in Allocate()
// and sends a release msg to the DHCP server.
func (d *DHCP) Release(args *skel.CmdArgs, _ *struct{}) error {
	conf := NetConf{}
	if err := json.Unmarshal(args.StdinData, &conf); err != nil {
		return fmt.Errorf("error parsing netconf: %v", err)
	}

	clientID := generateClientID(args.ContainerID, conf.Name, args.IfName)
	if l := d.getLease(clientID); l != nil {
		l.Stop()
		d.clearLease(clientID)
	}

	return nil
}

func (d *DHCP) getLease(clientID string) *DHCPLease {
	d.mux.Lock()
	defer d.mux.Unlock()

	// TODO(eyakubovich): hash it to avoid collisions
	l, ok := d.leases[clientID]
	if !ok {
		return nil
	}
	return l
}

func (d *DHCP) setLease(clientID string, l *DHCPLease) {
	d.mux.Lock()
	defer d.mux.Unlock()

	// TODO(eyakubovich): hash it to avoid collisions
	d.leases[clientID] = l
}

// func (d *DHCP) clearLease(contID, netName, ifName string) {
func (d *DHCP) clearLease(clientID string) {
	d.mux.Lock()
	defer d.mux.Unlock()

	// TODO(eyakubovich): hash it to avoid collisions
	delete(d.leases, clientID)
}

func getListener(socketPath string) (net.Listener, error) {
	l, err := activation.Listeners()
	if err != nil {
		return nil, err
	}

	switch {
	case len(l) == 0:
		if err := os.MkdirAll(filepath.Dir(socketPath), 0o700); err != nil {
			return nil, err
		}
		return net.Listen("unix", socketPath)

	case len(l) == 1:
		if l[0] == nil {
			return nil, fmt.Errorf("LISTEN_FDS=1 but no FD found")
		}
		return l[0], nil

	default:
		return nil, fmt.Errorf("Too many (%v) FDs passed through socket activation", len(l))
	}
}

func runDaemon(
	pidfilePath, hostPrefix, socketPath string,
	dhcpClientTimeout time.Duration, resendMax time.Duration, resendTimeout time.Duration,
	broadcast bool,
) error {
	// since other goroutines (on separate threads) will change namespaces,
	// ensure the RPC server does not get scheduled onto those
	runtime.LockOSThread()

	// Write the pidfile
	if pidfilePath != "" {
		if !filepath.IsAbs(pidfilePath) {
			return fmt.Errorf("Error writing pidfile %q: path not absolute", pidfilePath)
		}
		if err := os.WriteFile(pidfilePath, []byte(fmt.Sprintf("%d", os.Getpid())), 0o644); err != nil {
			return fmt.Errorf("Error writing pidfile %q: %v", pidfilePath, err)
		}
	}

	l, err := getListener(hostPrefix + socketPath)
	if err != nil {
		return fmt.Errorf("Error getting listener: %v", err)
	}

	srv := http.Server{}
	exit := make(chan os.Signal, 1)
	done := make(chan bool, 1)
	signal.Notify(exit, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-exit
		srv.Shutdown(context.TODO())
		os.Remove(hostPrefix + socketPath)
		os.Remove(pidfilePath)

		done <- true
	}()

	dhcp := newDHCP(dhcpClientTimeout, resendMax, resendTimeout)
	dhcp.hostNetnsPrefix = hostPrefix
	dhcp.broadcast = broadcast
	rpc.Register(dhcp)
	rpc.HandleHTTP()
	srv.Serve(l)

	<-done
	return nil
}
