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
	"fmt"
	"log"
	"math/rand"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/d2g/dhcp4"
	"github.com/d2g/dhcp4client"
	"github.com/vishvananda/netlink"

	"github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/plugins/pkg/ns"
)

// RFC 2131 suggests using exponential backoff, starting with 4sec
// and randomized to +/- 1sec
const (
	resendDelay0   = 4 * time.Second
	resendDelayMax = 62 * time.Second
)

// To speed up the retry for first few failures, we retry without
// backoff for a few times
const (
	resendFastDelay = 2 * time.Second
	resendFastMax   = 4
)

const (
	leaseStateBound = iota
	leaseStateRenewing
	leaseStateRebinding
)

// This implementation uses 1 OS thread per lease. This is because
// all the network operations have to be done in network namespace
// of the interface. This can be improved by switching to the proper
// namespace for network ops and using fewer threads. However, this
// needs to be done carefully as dhcp4client ops are blocking.

type DHCPLease struct {
	clientID      string
	ack           *dhcp4.Packet
	opts          dhcp4.Options
	link          netlink.Link
	renewalTime   time.Time
	rebindingTime time.Time
	expireTime    time.Time
	timeout       time.Duration
	resendMax     time.Duration
	broadcast     bool
	stopping      uint32
	stop          chan struct{}
	check         chan struct{}
	wg            sync.WaitGroup
	// list of requesting and providing options and if they are necessary / their value
	optsRequesting map[dhcp4.OptionCode]bool
	optsProviding  map[dhcp4.OptionCode][]byte
}

var requestOptionsDefault = map[dhcp4.OptionCode]bool{
	dhcp4.OptionRouter:     true,
	dhcp4.OptionSubnetMask: true,
}

func prepareOptions(cniArgs string, provideOptions []ProvideOption, requestOptions []RequestOption) (
	map[dhcp4.OptionCode]bool, map[dhcp4.OptionCode][]byte, error,
) {
	var optsRequesting map[dhcp4.OptionCode]bool
	var optsProviding map[dhcp4.OptionCode][]byte
	var err error
	// parse CNI args
	cniArgsParsed := map[string]string{}
	for _, argPair := range strings.Split(cniArgs, ";") {
		args := strings.SplitN(argPair, "=", 2)
		if len(args) > 1 {
			cniArgsParsed[args[0]] = args[1]
		}
	}

	// parse providing options map
	var optParsed dhcp4.OptionCode
	optsProviding = make(map[dhcp4.OptionCode][]byte)
	for _, opt := range provideOptions {
		optParsed, err = parseOptionName(string(opt.Option))
		if err != nil {
			return nil, nil, fmt.Errorf("Can not parse option %q: %w", opt.Option, err)
		}
		if len(opt.Value) > 0 {
			if len(opt.Value) > 255 {
				return nil, nil, fmt.Errorf("value too long for option %q: %q", opt.Option, opt.Value)
			}
			optsProviding[optParsed] = []byte(opt.Value)
		}
		if value, ok := cniArgsParsed[opt.ValueFromCNIArg]; ok {
			if len(value) > 255 {
				return nil, nil, fmt.Errorf("value too long for option %q from CNI_ARGS %q: %q", opt.Option, opt.ValueFromCNIArg, opt.Value)
			}
			optsProviding[optParsed] = []byte(value)
		}
	}

	// parse necessary options map
	optsRequesting = make(map[dhcp4.OptionCode]bool)
	skipRequireDefault := false
	for _, opt := range requestOptions {
		if opt.SkipDefault {
			skipRequireDefault = true
		}
		optParsed, err = parseOptionName(string(opt.Option))
		if err != nil {
			return nil, nil, fmt.Errorf("Can not parse option %q: %w", opt.Option, err)
		}
		optsRequesting[optParsed] = true
	}
	for k, v := range requestOptionsDefault {
		// only set if not skipping default and this value does not exists
		if _, ok := optsRequesting[k]; !ok && !skipRequireDefault {
			optsRequesting[k] = v
		}
	}
	return optsRequesting, optsProviding, err
}

// AcquireLease gets an DHCP lease and then maintains it in the background
// by periodically renewing it. The acquired lease can be released by
// calling DHCPLease.Stop()
func AcquireLease(
	clientID, netns, ifName string,
	optsRequesting map[dhcp4.OptionCode]bool, optsProviding map[dhcp4.OptionCode][]byte,
	timeout, resendMax time.Duration, broadcast bool,
) (*DHCPLease, error) {
	errCh := make(chan error, 1)
	l := &DHCPLease{
		clientID:       clientID,
		stop:           make(chan struct{}),
		check:          make(chan struct{}),
		timeout:        timeout,
		resendMax:      resendMax,
		broadcast:      broadcast,
		optsRequesting: optsRequesting,
		optsProviding:  optsProviding,
	}

	log.Printf("%v: acquiring lease", clientID)

	l.wg.Add(1)
	go func() {
		errCh <- ns.WithNetNSPath(netns, func(_ ns.NetNS) error {
			defer l.wg.Done()

			link, err := netlink.LinkByName(ifName)
			if err != nil {
				return fmt.Errorf("error looking up %q: %v", ifName, err)
			}

			l.link = link

			if err = l.acquire(); err != nil {
				return err
			}

			log.Printf("%v: lease acquired, expiration is %v", l.clientID, l.expireTime)

			errCh <- nil

			l.maintain()
			return nil
		})
	}()

	if err := <-errCh; err != nil {
		return nil, err
	}

	return l, nil
}

// Stop terminates the background task that maintains the lease
// and issues a DHCP Release
func (l *DHCPLease) Stop() {
	if atomic.CompareAndSwapUint32(&l.stopping, 0, 1) {
		close(l.stop)
	}
	l.wg.Wait()
}

func (l *DHCPLease) Check() {
	l.check <- struct{}{}
}

func (l *DHCPLease) getOptionsWithClientID() dhcp4.Options {
	opts := make(dhcp4.Options)
	opts[dhcp4.OptionClientIdentifier] = []byte(l.clientID)
	// client identifier's first byte is "type"
	newClientID := []byte{0}
	newClientID = append(newClientID, opts[dhcp4.OptionClientIdentifier]...)
	opts[dhcp4.OptionClientIdentifier] = newClientID
	return opts
}

func (l *DHCPLease) getAllOptions() dhcp4.Options {
	opts := l.getOptionsWithClientID()

	for k, v := range l.optsProviding {
		opts[k] = v
	}

	opts[dhcp4.OptionParameterRequestList] = []byte{}
	for k := range l.optsRequesting {
		opts[dhcp4.OptionParameterRequestList] = append(opts[dhcp4.OptionParameterRequestList], byte(k))
	}
	return opts
}

func (l *DHCPLease) acquire() error {
	c, err := newDHCPClient(l.link, l.timeout, l.broadcast)
	if err != nil {
		return err
	}
	defer c.Close()

	if (l.link.Attrs().Flags & net.FlagUp) != net.FlagUp {
		log.Printf("Link %q down. Attempting to set up", l.link.Attrs().Name)
		if err = netlink.LinkSetUp(l.link); err != nil {
			return err
		}
	}

	opts := l.getAllOptions()

	pkt, err := backoffRetry(l.resendMax, func() (*dhcp4.Packet, error) {
		ok, ack, err := DhcpRequest(c, opts)
		switch {
		case err != nil:
			return nil, err
		case !ok:
			return nil, fmt.Errorf("DHCP server NACK'd own offer")
		default:
			return &ack, nil
		}
	})
	if err != nil {
		return err
	}

	return l.commit(pkt)
}

func (l *DHCPLease) commit(ack *dhcp4.Packet) error {
	opts := ack.ParseOptions()

	leaseTime, err := parseLeaseTime(opts)
	if err != nil {
		return err
	}

	rebindingTime, err := parseRebindingTime(opts)
	if err != nil || rebindingTime > leaseTime {
		// Per RFC 2131 Section 4.4.5, it should default to 85% of lease time
		rebindingTime = leaseTime * 85 / 100
	}

	renewalTime, err := parseRenewalTime(opts)
	if err != nil || renewalTime > rebindingTime {
		// Per RFC 2131 Section 4.4.5, it should default to 50% of lease time
		renewalTime = leaseTime / 2
	}

	now := time.Now()
	l.expireTime = now.Add(leaseTime)
	l.renewalTime = now.Add(renewalTime)
	l.rebindingTime = now.Add(rebindingTime)
	l.ack = ack
	l.opts = opts

	return nil
}

func (l *DHCPLease) maintain() {
	state := leaseStateBound

	for {
		var sleepDur time.Duration

		switch state {
		case leaseStateBound:
			sleepDur = time.Until(l.renewalTime)
			if sleepDur <= 0 {
				log.Printf("%v: renewing lease", l.clientID)
				state = leaseStateRenewing
				continue
			}

		case leaseStateRenewing:
			if err := l.renew(); err != nil {
				log.Printf("%v: %v", l.clientID, err)

				if time.Now().After(l.rebindingTime) {
					log.Printf("%v: renewal time expired, rebinding", l.clientID)
					state = leaseStateRebinding
				}
			} else {
				log.Printf("%v: lease renewed, expiration is %v", l.clientID, l.expireTime)
				state = leaseStateBound
			}

		case leaseStateRebinding:
			if err := l.acquire(); err != nil {
				log.Printf("%v: %v", l.clientID, err)

				if time.Now().After(l.expireTime) {
					log.Printf("%v: lease expired, bringing interface DOWN", l.clientID)
					l.downIface()
					return
				}
			} else {
				log.Printf("%v: lease rebound, expiration is %v", l.clientID, l.expireTime)
				state = leaseStateBound
			}
		}

		select {
		case <-time.After(sleepDur):

		case <-l.check:
			log.Printf("%v: Checking lease", l.clientID)

		case <-l.stop:
			if err := l.release(); err != nil {
				log.Printf("%v: failed to release DHCP lease: %v", l.clientID, err)
			}
			return
		}
	}
}

func (l *DHCPLease) downIface() {
	if err := netlink.LinkSetDown(l.link); err != nil {
		log.Printf("%v: failed to bring %v interface DOWN: %v", l.clientID, l.link.Attrs().Name, err)
	}
}

func (l *DHCPLease) renew() error {
	c, err := newDHCPClient(l.link, l.timeout, l.broadcast)
	if err != nil {
		return err
	}
	defer c.Close()

	opts := l.getAllOptions()
	pkt, err := backoffRetry(l.resendMax, func() (*dhcp4.Packet, error) {
		ok, ack, err := DhcpRenew(c, *l.ack, opts)
		switch {
		case err != nil:
			return nil, err
		case !ok:
			return nil, fmt.Errorf("DHCP server did not renew lease")
		default:
			return &ack, nil
		}
	})
	if err != nil {
		return err
	}

	l.commit(pkt)
	return nil
}

func (l *DHCPLease) release() error {
	log.Printf("%v: releasing lease", l.clientID)

	c, err := newDHCPClient(l.link, l.timeout, l.broadcast)
	if err != nil {
		return err
	}
	defer c.Close()

	opts := l.getOptionsWithClientID()

	if err = DhcpRelease(c, *l.ack, opts); err != nil {
		return fmt.Errorf("failed to send DHCPRELEASE")
	}

	return nil
}

func (l *DHCPLease) IPNet() (*net.IPNet, error) {
	mask := parseSubnetMask(l.opts)
	if mask == nil {
		return nil, fmt.Errorf("DHCP option Subnet Mask not found in DHCPACK")
	}

	return &net.IPNet{
		IP:   l.ack.YIAddr(),
		Mask: mask,
	}, nil
}

func (l *DHCPLease) Gateway() net.IP {
	return parseRouter(l.opts)
}

func (l *DHCPLease) Routes() []*types.Route {
	routes := []*types.Route{}

	// RFC 3442 states that if Classless Static Routes (option 121)
	// exist, we ignore Static Routes (option 33) and the Router/Gateway.
	opt121Routes := parseCIDRRoutes(l.opts)
	if len(opt121Routes) > 0 {
		return append(routes, opt121Routes...)
	}

	// Append Static Routes
	routes = append(routes, parseRoutes(l.opts)...)

	// The CNI spec says even if there is a gateway specified, we must
	// add a default route in the routes section.
	if gw := l.Gateway(); gw != nil {
		_, defaultRoute, _ := net.ParseCIDR("0.0.0.0/0")
		routes = append(routes, &types.Route{Dst: *defaultRoute, GW: gw})
	}

	return routes
}

// jitter returns a random value within [-span, span) range
func jitter(span time.Duration) time.Duration {
	return time.Duration(float64(span) * (2.0*rand.Float64() - 1.0))
}

func backoffRetry(resendMax time.Duration, f func() (*dhcp4.Packet, error)) (*dhcp4.Packet, error) {
	baseDelay := resendDelay0
	var sleepTime time.Duration
	fastRetryLimit := resendFastMax
	for {
		pkt, err := f()
		if err == nil {
			return pkt, nil
		}

		log.Print(err)

		if fastRetryLimit == 0 {
			sleepTime = baseDelay + jitter(time.Second)
		} else {
			sleepTime = resendFastDelay + jitter(time.Second)
			fastRetryLimit--
		}

		log.Printf("retrying in %f seconds", sleepTime.Seconds())

		time.Sleep(sleepTime)

		// only adjust delay time if we are in normal backoff stage
		if baseDelay < resendMax && fastRetryLimit == 0 {
			baseDelay *= 2
		} else if fastRetryLimit == 0 { // only break if we are at normal delay
			break
		}
	}

	return nil, errNoMoreTries
}

func newDHCPClient(
	link netlink.Link,
	timeout time.Duration,
	broadcast bool,
) (*dhcp4client.Client, error) {
	pktsock, err := dhcp4client.NewPacketSock(link.Attrs().Index)
	if err != nil {
		return nil, err
	}

	return dhcp4client.New(
		dhcp4client.HardwareAddr(link.Attrs().HardwareAddr),
		dhcp4client.Timeout(timeout),
		dhcp4client.Broadcast(broadcast),
		dhcp4client.Connection(pktsock),
	)
}
