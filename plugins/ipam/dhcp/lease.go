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
	"errors"
	"fmt"
	"log"
	"math/rand"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	dhcp4 "github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv4/nclient4"
	"github.com/vishvananda/netlink"

	"github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/plugins/pkg/netlinksafe"
	"github.com/containernetworking/plugins/pkg/ns"
)

// RFC 2131 suggests using exponential backoff, starting with 4sec
// and randomized to +/- 1sec
const (
	resendDelay0         = 4 * time.Second
	resendDelayMax       = 62 * time.Second
	defaultLeaseTime     = 60 * time.Minute
	defaultResendTimeout = 208 * time.Second // fast resend + backoff resend
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

// Timing for retrying link existence check
const (
	linkCheckDelay0       = 1 * time.Second
	linkCheckRetryMax     = 10 * time.Second
	linkCheckTotalTimeout = 30 * time.Second
)

// This implementation uses 1 OS thread per lease. This is because
// all the network operations have to be done in network namespace
// of the interface. This can be improved by switching to the proper
// namespace for network ops and using fewer threads. However, this
// needs to be done carefully as dhcp4client ops are blocking.

type DHCPLease struct {
	clientID      string
	latestLease   *nclient4.Lease
	link          netlink.Link
	linkName      string
	renewalTime   time.Time
	rebindingTime time.Time
	expireTime    time.Time
	timeout       time.Duration
	resendMax     time.Duration
	resendTimeout time.Duration
	broadcast     bool
	stopping      uint32
	stop          chan struct{}
	check         chan struct{}
	wg            sync.WaitGroup
	cancelFunc    context.CancelFunc
	ctx           context.Context
	// list of requesting and providing options and if they are necessary / their value
	opts []dhcp4.Option
}

var requestOptionsDefault = []dhcp4.OptionCode{
	dhcp4.OptionRouter,
	dhcp4.OptionSubnetMask,
}

func prepareOptions(cniArgs string, provideOptions []ProvideOption, requestOptions []RequestOption) (
	[]dhcp4.Option, error,
) {
	var opts []dhcp4.Option

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
	for _, opt := range provideOptions {
		optParsed, err = parseOptionName(string(opt.Option))
		if err != nil {
			return nil, fmt.Errorf("Can not parse option %q: %w", opt.Option, err)
		}
		if len(opt.Value) > 0 {
			if len(opt.Value) > 255 {
				return nil, fmt.Errorf("value too long for option %q: %q", opt.Option, opt.Value)
			}
			opts = append(opts, dhcp4.Option{Code: optParsed, Value: dhcp4.String(opt.Value)})
		}
		if value, ok := cniArgsParsed[opt.ValueFromCNIArg]; ok {
			if len(value) > 255 {
				return nil, fmt.Errorf("value too long for option %q from CNI_ARGS %q: %q", opt.Option, opt.ValueFromCNIArg, opt.Value)
			}
			opts = append(opts, dhcp4.Option{Code: optParsed, Value: dhcp4.String(value)})
		}
	}

	// parse necessary options map
	var optsRequesting dhcp4.OptionCodeList
	skipRequireDefault := false
	for _, opt := range requestOptions {
		if opt.SkipDefault {
			skipRequireDefault = true
		}
		if opt.Option == "" {
			continue
		}
		optParsed, err = parseOptionName(string(opt.Option))
		if err != nil {
			return nil, fmt.Errorf("Can not parse option %q: %w", opt.Option, err)
		}
		optsRequesting.Add(optParsed)
	}
	if !skipRequireDefault {
		for _, opt := range requestOptionsDefault {
			optsRequesting.Add(opt)
		}
	}
	if len(optsRequesting) > 0 {
		opts = append(opts, dhcp4.Option{Code: dhcp4.OptionParameterRequestList, Value: optsRequesting})
	}

	return opts, err
}

// AcquireLease gets an DHCP lease and then maintains it in the background
// by periodically renewing it. The acquired lease can be released by
// calling DHCPLease.Stop()
func AcquireLease(
	clientID, netns, ifName string,
	opts []dhcp4.Option,
	timeout, resendMax time.Duration, resendTimeout time.Duration, broadcast bool,
) (*DHCPLease, error) {
	errCh := make(chan error, 1)

	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)

	l := &DHCPLease{
		clientID:      clientID,
		stop:          make(chan struct{}),
		check:         make(chan struct{}),
		timeout:       timeout,
		resendMax:     resendMax,
		resendTimeout: resendTimeout,
		broadcast:     broadcast,
		opts:          opts,
		cancelFunc:    cancel,
		ctx:           ctx,
	}

	log.Printf("%v: acquiring lease", clientID)

	l.wg.Add(1)
	go func() {
		errCh <- ns.WithNetNSPath(netns, func(_ ns.NetNS) error {
			defer l.wg.Done()

			link, err := netlinksafe.LinkByName(ifName)
			if err != nil {
				return fmt.Errorf("error looking up %q: %v", ifName, err)
			}

			l.link = link
			l.linkName = link.Attrs().Name

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
		l.cancelFunc()
	}
	l.wg.Wait()
}

func (l *DHCPLease) Check() {
	l.check <- struct{}{}
}

func withClientID(clientID string) dhcp4.Modifier {
	return func(d *dhcp4.DHCPv4) {
		optClientID := []byte{0}
		optClientID = append(optClientID, []byte(clientID)...)
		d.Options.Update(dhcp4.OptClientIdentifier(optClientID))
	}
}

func withAllOptions(l *DHCPLease) dhcp4.Modifier {
	return func(d *dhcp4.DHCPv4) {
		for _, opt := range l.opts {
			d.Options.Update(opt)
		}
	}
}

func (l *DHCPLease) acquire() error {
	if (l.link.Attrs().Flags & net.FlagUp) != net.FlagUp {
		log.Printf("Link %q down. Attempting to set up", l.linkName)
		if err := netlink.LinkSetUp(l.link); err != nil {
			return err
		}
	}

	c, err := newDHCPClient(l.link, l.timeout)
	if err != nil {
		return err
	}
	defer c.Close()

	timeoutCtx, cancel := context.WithTimeoutCause(l.ctx, l.resendTimeout, errNoMoreTries)
	defer cancel()
	pkt, err := backoffRetry(timeoutCtx, l.resendMax, func() (*nclient4.Lease, error) {
		return c.Request(
			timeoutCtx,
			withClientID(l.clientID),
			withAllOptions(l),
		)
	})
	if err != nil {
		return err
	}

	l.commit(pkt)
	return nil
}

func (l *DHCPLease) commit(lease *nclient4.Lease) {
	l.latestLease = lease
	ack := lease.ACK

	leaseTime := ack.IPAddressLeaseTime(defaultLeaseTime)
	rebindingTime := ack.IPAddressRebindingTime(leaseTime * 85 / 100)
	renewalTime := ack.IPAddressRenewalTime(leaseTime / 2)

	now := time.Now()
	l.expireTime = now.Add(leaseTime)
	l.renewalTime = now.Add(renewalTime)
	l.rebindingTime = now.Add(rebindingTime)
}

func (l *DHCPLease) maintain() {
	state := leaseStateBound

	for {
		var sleepDur time.Duration

		linkCheckCtx, cancel := context.WithTimeoutCause(l.ctx, l.resendTimeout, errNoMoreTries)
		defer cancel()
		linkExists, _ := checkLinkExistsWithBackoff(linkCheckCtx, l.linkName)
		if !linkExists {
			log.Printf("%v: interface %s no longer exists or link check failed, terminating lease maintenance", l.clientID, l.linkName)
			return
		}

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

func checkLinkExistsWithBackoff(ctx context.Context, linkName string) (bool, error) {
	baseDelay := linkCheckDelay0
	for {
		exists, err := checkLinkByName(linkName)
		if err == nil {
			return exists, nil
		}

		select {
		case <-ctx.Done():
			return false, ctx.Err() // Context's done, return with its error
		case <-time.After(baseDelay):
			if baseDelay < linkCheckRetryMax {
				baseDelay *= 2
			}
		}
	}
}

func checkLinkByName(linkName string) (bool, error) {
	_, err := netlinksafe.LinkByName(linkName)
	if err != nil {
		linkNotFoundErr := &netlink.LinkNotFoundError{}
		if errors.As(err, linkNotFoundErr) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func (l *DHCPLease) downIface() {
	if err := netlink.LinkSetDown(l.link); err != nil {
		log.Printf("%v: failed to bring %v interface DOWN: %v", l.clientID, l.linkName, err)
	}
}

func (l *DHCPLease) renew() error {
	c, err := newDHCPClient(l.link, l.timeout)
	if err != nil {
		return err
	}
	defer c.Close()

	timeoutCtx, cancel := context.WithTimeoutCause(l.ctx, l.resendTimeout, errNoMoreTries)
	defer cancel()
	lease, err := backoffRetry(timeoutCtx, l.resendMax, func() (*nclient4.Lease, error) {
		return c.Renew(
			timeoutCtx,
			l.latestLease,
			withClientID(l.clientID),
			withAllOptions(l),
		)
	})
	if err != nil {
		return err
	}

	l.commit(lease)
	return nil
}

func (l *DHCPLease) release() error {
	log.Printf("%v: releasing lease", l.clientID)

	c, err := newDHCPClient(l.link, l.timeout)
	if err != nil {
		return err
	}
	defer c.Close()

	if err = c.Release(l.latestLease, withClientID(l.clientID)); err != nil {
		return fmt.Errorf("failed to send DHCPRELEASE")
	}

	return nil
}

func (l *DHCPLease) IPNet() (*net.IPNet, error) {
	ack := l.latestLease.ACK

	mask := ack.SubnetMask()
	if mask == nil {
		return nil, fmt.Errorf("DHCP option Subnet Mask not found in DHCPACK")
	}

	return &net.IPNet{
		IP:   ack.YourIPAddr,
		Mask: mask,
	}, nil
}

func (l *DHCPLease) Gateway() net.IP {
	ack := l.latestLease.ACK
	gws := ack.Router()
	if len(gws) > 0 {
		return gws[0]
	}
	return nil
}

func (l *DHCPLease) Routes() []*types.Route {
	routes := []*types.Route{}

	ack := l.latestLease.ACK

	// RFC 3442 states that if Classless Static Routes (option 121)
	// exist, we ignore Static Routes (option 33) and the Router/Gateway.
	opt121Routes := ack.ClasslessStaticRoute()
	if len(opt121Routes) > 0 {
		for _, r := range opt121Routes {
			route := &types.Route{Dst: *r.Dest, GW: r.Router}
			// if router is not specified, add SCOPE_LINK so routes are installed
			if r.Router.IsUnspecified() {
				scopeLinkValue := int(netlink.SCOPE_LINK)
				route.Scope = &scopeLinkValue
			}
			routes = append(routes, route)
		}
		return routes
	}

	// Append Static Routes
	if ack.Options.Has(dhcp4.OptionStaticRoutingTable) {
		routes = append(routes, parseRoutes(ack.Options.Get(dhcp4.OptionStaticRoutingTable))...)
	}

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

func backoffRetry(ctx context.Context, resendMax time.Duration, f func() (*nclient4.Lease, error)) (*nclient4.Lease, error) {
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

		select {
		case <-ctx.Done():
			return nil, context.Cause(ctx)
		case <-time.After(sleepTime):
			// only adjust delay time if we are in normal backoff stage
			if baseDelay < resendMax && fastRetryLimit == 0 {
				baseDelay *= 2
			}
		}
	}
}

func newDHCPClient(
	link netlink.Link,
	timeout time.Duration,
	clientOpts ...nclient4.ClientOpt,
) (*nclient4.Client, error) {
	clientOpts = append(clientOpts, nclient4.WithTimeout(timeout))
	return nclient4.New(link.Attrs().Name, clientOpts...)
}
