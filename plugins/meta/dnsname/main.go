// Copyright 2017 CNI authors
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

// This is a post-setup plugin that establishes port forwarding - using iptables,
// from the host's network interface(s) to a pod's network interface.
//
// It is intended to be used as a chained CNI plugin, and determines the container
// IP from the previous result. If the result includes an IPv6 address, it will
// also be configured. (IPTables will not forward cross-family).
//
// This has one notable limitation: it does not perform any kind of reservation
// of the actual host port. If there is a service on the host, it will have all
// its traffic captured by the container. If another container also claims a given
// port, it will caputure the traffic - it is last-write-wins.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/cni/pkg/types/current"
	"github.com/containernetworking/cni/pkg/version"
	bv "github.com/containernetworking/plugins/pkg/utils/buildversion"
	"github.com/sirupsen/logrus"
)

func cmdAdd(args *skel.CmdArgs) error {
	if err := findDNSMasq(); err != nil {
		return ErrBinaryNotFound
	}
	netConf, result, podname, err := parseConfig(args.StdinData, args.Args)
	if err != nil {
		return fmt.Errorf("failed to parse config: %v", err)
	}
	if netConf.PrevResult == nil {
		return fmt.Errorf("must be called as chained plugin")
	}
	ips, err := getIPs(result)
	if err != nil {
		return err
	}

	dnsNameConf, err := newDNSMasqFile(netConf.DomainName, result.Interfaces[0].Name, netConf.Name)
	if err != nil {
		return err
	}
	domainBaseDir := filepath.Dir(dnsNameConf.PidFile)
	// Check if the configuration file directory exists, else make it
	if _, err := os.Stat(domainBaseDir); os.IsNotExist(err) {
		if makeDirErr := os.MkdirAll(domainBaseDir, 0700); makeDirErr != nil {
			return makeDirErr
		}
	}
	// we use the configuration directory for our locking mechanism but read/write and hup
	lock, err := getLock(domainBaseDir)
	if err != nil {
		return err
	}
	defer func() {
		if err := lock.release(); err != nil {
			logrus.Errorf("unable to release lock for '%s': %q", dnsNameConf.AddOnHostsFile, err)
		}
	}()
	if err := checkForDNSMasqConfFile(dnsNameConf); err != nil {
		return err
	}
	if err := appendToFile(dnsNameConf.AddOnHostsFile, podname, ips); err != nil {
		return err
	}
	// Now we need to HUP
	if err := dnsNameConf.hup(); err != nil {
		return err
	}
	nameservers, err := getInterfaceAddresses(dnsNameConf)
	if err != nil {
		return err
	}
	// keep anything that was passed in already
	nameservers = append(nameservers, result.DNS.Nameservers...)
	result.DNS.Nameservers = nameservers
	// Pass through the previous result
	return types.PrintResult(result, netConf.CNIVersion)
}

func cmdDel(args *skel.CmdArgs) error {
	if err := findDNSMasq(); err != nil {
		return ErrBinaryNotFound
	}
	netConf, result, podname, err := parseConfig(args.StdinData, args.Args)
	if err != nil {
		return fmt.Errorf("failed to parse config: %v", err)
	}
	if result == nil {
		return nil
	}
	dnsNameConf, err := newDNSMasqFile(netConf.DomainName, result.Interfaces[0].Name, netConf.Name)
	if err != nil {
		return err
	}
	domainBaseDir := filepath.Dir(dnsNameConf.PidFile)
	lock, err := getLock(domainBaseDir)
	if err != nil {
		return err
	}
	defer func() {
		// if the lock isn't given up by another process
		if err := lock.release(); err != nil {
			logrus.Errorf("unable to release lock for '%s': %q", domainBaseDir, err)
		}
	}()
	shouldHUP, err := removeFromFile(filepath.Join(domainBaseDir, hostsFileName), podname)
	if err != nil {
		return err
	}
	if !shouldHUP {
		// if there are no hosts, we should just stop the dnsmasq instance to not take
		// system resources
		return dnsNameConf.stop()
	}
	// Now we need to HUP
	return dnsNameConf.hup()
}

func main() {
	skel.PluginMain(cmdAdd, cmdCheck, cmdDel, version.All, bv.BuildString("dnsname"))
}

func cmdCheck(args *skel.CmdArgs) error {
	var (
		conffiles []string
	)
	if err := findDNSMasq(); err != nil {
		return ErrBinaryNotFound
	}
	netConf, result, podname, err := parseConfig(args.StdinData, args.Args)
	if err != nil {
		return fmt.Errorf("failed to parse config: %v", err)
	}

	_ = podname

	// Ensure we have previous result.
	if result == nil {
		return fmt.Errorf("Required prevResult missing")
	}
	dnsNameConf, err := newDNSMasqFile(netConf.DomainName, result.Interfaces[0].Name, netConf.Name)
	if err != nil {
		return err
	}
	domainBaseDir := filepath.Dir(dnsNameConf.PidFile)
	lock, err := getLock(domainBaseDir)
	if err != nil {
		return err
	}
	defer func() {
		// if the lock isn't given up by another process
		if err := lock.release(); err != nil {
			logrus.Errorf("unable to release lock for '%s': %q", domainBaseDir, err)
		}
	}()

	pid, err := dnsNameConf.getPidProcess()
	if err != nil {
		return err
	}

	// Ensure the dnsmasq instance is running
	if !isRunning(pid) {
		return errors.New("dnsmasq instance not running")
	}
	// Above will make sure the pidfile exists
	files, err := ioutil.ReadDir(dnsNameConfPath)
	if err != nil {
		return err
	}
	for _, f := range files {
		conffiles = append(conffiles, f.Name())
	}
	if !stringInSlice("addnhosts", conffiles) {
		return errors.New("addnhost file missing from configuration")
	}
	if !stringInSlice("dnsmasq.conf", conffiles) {
		return errors.New("dnsmasq.conf file missing from configuration")
	}
	return nil
}

// stringInSlice is simple util to check for the presence of a string
// in a string slice
func stringInSlice(s string, slice []string) bool {
	for _, sl := range slice {
		if s == sl {
			return true
		}
	}
	return false
}

type podname struct {
	types.CommonArgs
	K8S_POD_NAME types.UnmarshallableString `json:"podname,omitempty"`
}

// parseConfig parses the supplied configuration (and prevResult) from stdin.
func parseConfig(stdin []byte, args string) (*DNSNameConf, *current.Result, string, error) {
	conf := DNSNameConf{}
	if err := json.Unmarshal(stdin, &conf); err != nil {
		return nil, nil, "", fmt.Errorf("failed to parse network configuration: %v", err)
	}
	// Parse previous result.
	var result *current.Result
	if conf.RawPrevResult != nil {
		var err error
		if err = version.ParsePrevResult(&conf.NetConf); err != nil {
			return nil, nil, "", fmt.Errorf("could not parse prevResult: %v", err)
		}
		result, err = current.NewResultFromResult(conf.PrevResult)
		if err != nil {
			return nil, nil, "", fmt.Errorf("could not convert result to current version: %v", err)
		}
	}
	e := podname{}
	if err := types.LoadArgs(args, &e); err != nil {
		return nil, nil, "", err
	}
	return &conf, result, string(e.K8S_POD_NAME), nil
}

func findDNSMasq() error {
	_, err := exec.LookPath("dnsmasq")
	return err
}
