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

// This is the Source Based Routing plugin that sets up source based routing.
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net"

	"github.com/alexflint/go-filemutex"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	current "github.com/containernetworking/cni/pkg/types/100"
	"github.com/containernetworking/cni/pkg/version"
	"github.com/containernetworking/plugins/pkg/netlinksafe"
	"github.com/containernetworking/plugins/pkg/ns"
	bv "github.com/containernetworking/plugins/pkg/utils/buildversion"
)

const firstTableID = 100

// PluginConf is the configuration document passed in.
type PluginConf struct {
	types.NetConf

	// This is the previous result, when called in the context of a chained
	// plugin. Because this plugin supports multiple versions, we'll have to
	// parse this in two passes. If your plugin is not chained, this can be
	// removed (though you may wish to error if a non-chainable plugin is
	// chained).
	RawPrevResult *map[string]interface{} `json:"prevResult"`
	PrevResult    *current.Result         `json:"-"`

	// Add plugin-specific flags here
	Table *int `json:"table,omitempty"`
	// Gateways allows specifying static/hardcoded gateway IP addresses
	// If set, these will be used instead of the gateway from prevResult
	// Supports dual-stack: provide one IPv4 and/or one IPv6 gateway
	// Note: Currently applies the same gateway to all IPs of the same family.
	// Per-subnet gateway mapping is not yet supported.
	Gateways []string `json:"gateways,omitempty"`
	// AddSourceHints adds source IP hints to subnet routes in the main table,
	// enabling destination-based routing when no explicit source IP is specified.
	// This allows both source-based and destination-based routing to work together.
	AddSourceHints bool `json:"addSourceHints,omitempty"`
}

// Wrapper that does a lock before and unlock after operations to serialise
// this plugin.
func withLockAndNetNS(nspath string, toRun func(_ ns.NetNS) error) error {
	// We lock on the network namespace to ensure that no other instance
	// clashes with this one.
	log.Printf("Network namespace to use and lock: %s", nspath)
	lock, err := filemutex.New(nspath)
	if err != nil {
		return err
	}

	err = lock.Lock()
	if err != nil {
		return err
	}

	err = ns.WithNetNSPath(nspath, toRun)
	if err != nil {
		return err
	}

	// Cleaner to unlock even though about to exit
	err = lock.Unlock()

	return err
}

// parseConfig parses the supplied configuration (and prevResult) from stdin.
func parseConfig(stdin []byte) (*PluginConf, error) {
	conf := PluginConf{}

	if err := json.Unmarshal(stdin, &conf); err != nil {
		return nil, fmt.Errorf("failed to parse network configuration: %v", err)
	}

	// Parse previous result.
	if conf.RawPrevResult != nil {
		resultBytes, err := json.Marshal(conf.RawPrevResult)
		if err != nil {
			return nil, fmt.Errorf("could not serialize prevResult: %v", err)
		}
		res, err := version.NewResult(conf.CNIVersion, resultBytes)
		if err != nil {
			return nil, fmt.Errorf("could not parse prevResult: %v", err)
		}
		conf.RawPrevResult = nil
		conf.PrevResult, err = current.NewResultFromResult(res)
		if err != nil {
			return nil, fmt.Errorf("could not convert result to current version: %v", err)
		}
	}
	// End previous result parsing

	return &conf, nil
}

// getIPCfgs finds the IPs on the supplied interface, returning as IPConfig structures
func getIPCfgs(iface string, prevResult *current.Result) ([]*current.IPConfig, error) {
	if len(prevResult.IPs) == 0 {
		// No IP addresses; that makes no sense. Pack it in.
		return nil, fmt.Errorf("No IP addresses supplied on interface: %s", iface)
	}

	// We do a single interface name, stored in args.IfName
	log.Printf("Checking for relevant interface: %s", iface)

	// ips contains the IPConfig structures that were passed, filtered somewhat
	ipCfgs := make([]*current.IPConfig, 0, len(prevResult.IPs))

	for _, ipCfg := range prevResult.IPs {
		// IPs have an interface that is an index into the interfaces array.
		// We assume a match if this index is missing.
		if ipCfg.Interface == nil {
			log.Printf("No interface for IP address %s", ipCfg.Address.IP)
			ipCfgs = append(ipCfgs, ipCfg)
			continue
		}

		// Skip all IPs we know belong to an interface with the wrong name.
		intIdx := *ipCfg.Interface
		if intIdx >= 0 && intIdx < len(prevResult.Interfaces) && prevResult.Interfaces[intIdx].Name != iface {
			log.Printf("Incorrect interface for IP address %s", ipCfg.Address.IP)
			continue
		}

		log.Printf("Found IP address %s", ipCfg.Address.IP.String())
		ipCfgs = append(ipCfgs, ipCfg)
	}

	return ipCfgs, nil
}

// cmdAdd is called for ADD requests
func cmdAdd(args *skel.CmdArgs) error {
	conf, err := parseConfig(args.StdinData)
	if err != nil {
		return err
	}

	log.Printf("Configure SBR for new interface %s - previous result: %v",
		args.IfName, conf.PrevResult)

	if conf.PrevResult == nil {
		return fmt.Errorf("This plugin must be called as chained plugin")
	}

	// Get the list of relevant IPs.
	ipCfgs, err := getIPCfgs(args.IfName, conf.PrevResult)
	if err != nil {
		return err
	}

	// Do the actual work.
	err = withLockAndNetNS(args.Netns, func(_ ns.NetNS) error {
		if conf.Table != nil {
			return doRoutesWithTable(ipCfgs, *conf.Table)
		}
		return doRoutes(ipCfgs, args.IfName, conf.Gateways, conf.AddSourceHints)
	})
	if err != nil {
		return err
	}

	// Pass through the result for the next plugin
	return types.PrintResult(conf.PrevResult, conf.CNIVersion)
}

// getNextTableID picks the first free table id from a giveen candidate id
func getNextTableID(rules []netlink.Rule, routes []netlink.Route, candidateID int) int {
	table := candidateID
	for {
		foundExisting := false
		for _, rule := range rules {
			if rule.Table == table {
				foundExisting = true
				break
			}
		}

		for _, route := range routes {
			if route.Table == table {
				foundExisting = true
				break
			}
		}

		if foundExisting {
			table++
		} else {
			break
		}
	}
	return table
}

// doRoutes does all the work to set up routes and rules during an add.
func doRoutes(ipCfgs []*current.IPConfig, iface string, staticGateways []string, addSourceHints bool) error {
	// Get a list of rules and routes ready.
	rules, err := netlinksafe.RuleList(netlink.FAMILY_ALL)
	if err != nil {
		return fmt.Errorf("Failed to list all rules: %v", err)
	}

	routes, err := netlinksafe.RouteList(nil, netlink.FAMILY_ALL)
	if err != nil {
		return fmt.Errorf("Failed to list all routes: %v", err)
	}

	// Pick a table ID to use. We pick the first table ID from firstTableID
	// on that has no existing rules mapping to it and no existing routes in
	// it.
	table := getNextTableID(rules, routes, firstTableID)
	log.Printf("First unreferenced table: %d", table)

	link, err := netlinksafe.LinkByName(iface)
	if err != nil {
		return fmt.Errorf("Cannot find network interface %s: %v", iface, err)
	}

	linkIndex := link.Attrs().Index

	// Get all routes for the interface in the default routing table
	routes, err = netlinksafe.RouteList(link, netlink.FAMILY_ALL)
	if err != nil {
		return fmt.Errorf("Unable to list routes: %v", err)
	}

	// Parse static gateways if provided (supports dual-stack: one IPv4, one IPv6)
	var staticGwV4, staticGwV6 net.IP
	if len(staticGateways) > 2 {
		return fmt.Errorf("gateways list cannot contain more than 2 entries (one IPv4, one IPv6)")
	}
	for _, gw := range staticGateways {
		ip := net.ParseIP(gw)
		if ip == nil {
			return fmt.Errorf("invalid static gateway IP address: %s", gw)
		}
		if ip.To4() != nil {
			if staticGwV4 != nil {
				// We already have an IPv4 static gateway
				return fmt.Errorf("gateways list contains multiple IPv4 addresses: %s and %s", staticGwV4, gw)
			}
			staticGwV4 = ip
			log.Printf("Using static IPv4 gateway: %s", ip)
		} else {
			if staticGwV6 != nil {
				// We already have an IPv6 static gateway
				return fmt.Errorf("gateways list contains multiple IPv6 addresses: %s and %s", staticGwV6, gw)
			}
			staticGwV6 = ip
			log.Printf("Using static IPv6 gateway: %s", ip)
		}
	}

	// Loop through setting up source based rules and default routes.
	for _, ipCfg := range ipCfgs {
		log.Printf("Set rule for source %s", ipCfg.String())
		rule := netlink.NewRule()
		rule.Table = table

		// Source must be restricted to a single IP, not a full subnet
		var src net.IPNet
		src.IP = ipCfg.Address.IP
		if src.IP.To4() != nil {
			src.Mask = net.CIDRMask(32, 32)
		} else {
			src.Mask = net.CIDRMask(128, 128)
		}

		log.Printf("Source to use %s", src.String())
		rule.Src = &src

		if err = netlink.RuleAdd(rule); err != nil {
			return fmt.Errorf("Failed to add rule: %v", err)
		}

		// Determine which gateway to use: static gateway takes precedence
		// Match gateway by IP family (IPv4 vs IPv6)
		var gateway net.IP
		isIPv4 := ipCfg.Address.IP.To4() != nil

		switch {
		case isIPv4 && staticGwV4 != nil:
			gateway = staticGwV4
		case !isIPv4 && staticGwV6 != nil:
			gateway = staticGwV6
		case ipCfg.Gateway != nil:
			gateway = ipCfg.Gateway
		}

		// Add a default route, since this may have been removed by previous
		// plugin.
		if gateway != nil {
			log.Printf("Adding default route to gateway %s", gateway.String())

			var dest net.IPNet
			if ipCfg.Address.IP.To4() != nil {
				dest.IP = net.IPv4zero
				dest.Mask = net.CIDRMask(0, 32)
			} else {
				dest.IP = net.IPv6zero
				dest.Mask = net.CIDRMask(0, 128)
			}

			route := netlink.Route{
				Dst:       &dest,
				Gw:        gateway,
				Table:     table,
				LinkIndex: linkIndex,
			}

			err = netlink.RouteAdd(&route)
			if err != nil {
				return fmt.Errorf("Failed to add default route to %s: %v",
					gateway.String(),
					err)
			}
		}

		// Copy the previously added routes for the interface to the correct
		// table; all the routes have been added to the interface anyway but
		// in the wrong table, so instead of removing them we just move them
		// to the table we want them in.
		for _, r := range routes {
			if ipCfg.Address.Contains(r.Src) || ipCfg.Address.Contains(r.Gw) ||
				(r.Src == nil && r.Gw == nil) {
				// (r.Src == nil && r.Gw == nil) is inferred as a generic route
				log.Printf("Copying route %s from table %d to %d",
					r.String(), r.Table, table)

				r.Table = table

				// Reset the route flags since if it is dynamically created,
				// adding it to the new table will fail with "invalid argument"
				r.Flags = 0

				// We use route replace in case the route already exists, which
				// is possible for the default gateway we added above.
				err = netlink.RouteReplace(&r)
				if err != nil {
					return fmt.Errorf("Failed to readd route: %v", err)
				}
			}
		}

		// Use a different table for each ipCfg
		table++
		table = getNextTableID(rules, routes, table)
	}

	// Handle routes in the default routing table
	if addSourceHints {
		// Keep or re-add subnet routes in main table with source IP hints
		// for destination-based routing when no explicit source IP is specified
		log.Printf("Adding source IP hints to subnet routes in main table")

		for _, ipCfg := range ipCfgs {
			// Find the subnet route for this IP
			subnet := &net.IPNet{
				IP:   ipCfg.Address.IP.Mask(ipCfg.Address.Mask),
				Mask: ipCfg.Address.Mask,
			}

			log.Printf("Adding/replacing route for subnet %s with src hint %s in main table",
				subnet.String(), ipCfg.Address.IP.String())

			// Add route to main table with source IP hint
			route := netlink.Route{
				LinkIndex: linkIndex,
				Dst:       subnet,
				Src:       ipCfg.Address.IP,
				Table:     unix.RT_TABLE_MAIN,
				Scope:     netlink.SCOPE_LINK,
			}

			// Use RouteReplace to update if it exists
			err := netlink.RouteReplace(&route)
			if err != nil {
				log.Printf("Warning: Failed to add subnet route to main table: %v", err)
				// Don't fail completely, just warn
			}
		}

		// Delete non-subnet routes from main table (gateway routes, etc.)
		for _, route := range routes {
			// Skip subnet routes (scope link), only delete other routes
			if route.Scope != netlink.SCOPE_LINK {
				log.Printf("Deleting non-subnet route %s from table %d", route.String(), route.Table)
				err := netlink.RouteDel(&route)
				if err != nil {
					log.Printf("Warning: Failed to delete route: %v", err)
				}
			}
		}
	} else {
		// Not deleting them while copying to accommodate for multiple ipCfgs from
		// the same subnet. Else, (error for network is unreachable while adding gateway)
		for _, route := range routes {
			log.Printf("Deleting route %s from table %d", route.String(), route.Table)
			err := netlink.RouteDel(&route)
			if err != nil {
				return fmt.Errorf("Failed to delete route: %v", err)
			}
		}
	}

	return nil
}

func doRoutesWithTable(ipCfgs []*current.IPConfig, table int) error {
	for _, ipCfg := range ipCfgs {
		log.Printf("Set rule for source %s", ipCfg.String())
		rule := netlink.NewRule()
		rule.Table = table

		// Source must be restricted to a single IP, not a full subnet
		var src net.IPNet
		src.IP = ipCfg.Address.IP
		if src.IP.To4() != nil {
			src.Mask = net.CIDRMask(32, 32)
		} else {
			src.Mask = net.CIDRMask(128, 128)
		}

		log.Printf("Source to use %s", src.String())
		rule.Src = &src

		if err := netlink.RuleAdd(rule); err != nil {
			return fmt.Errorf("failed to add rule: %v", err)
		}
	}

	return nil
}

// cmdDel is called for DELETE requests
func cmdDel(args *skel.CmdArgs) error {
	// We care a bit about config because it sets log level.
	conf, err := parseConfig(args.StdinData)
	if err != nil {
		return err
	}

	log.Printf("Cleaning up SBR for %s", args.IfName)
	err = withLockAndNetNS(args.Netns, func(_ ns.NetNS) error {
		return tidyRules(args.IfName, conf.Table)
	})

	return err
}

// Tidy up the rules for the deleted interface
func tidyRules(iface string, table *int) error {
	// We keep on going on rule deletion error, but return the last failure.
	var errReturn error
	var err error
	var rules []netlink.Rule

	if table != nil {
		rules, err = netlinksafe.RuleListFiltered(
			netlink.FAMILY_ALL,
			&netlink.Rule{
				Table: *table,
			},
			netlink.RT_FILTER_TABLE,
		)
		if err != nil {
			log.Printf("Failed to list rules of table %d to tidy: %v", *table, err)
			return fmt.Errorf("failed to list rules of table %d to tidy: %v", *table, err)
		}
	} else {
		rules, err = netlinksafe.RuleList(netlink.FAMILY_ALL)
		if err != nil {
			log.Printf("Failed to list all rules to tidy: %v", err)
			return fmt.Errorf("Failed to list all rules to tidy: %v", err)
		}
	}

	link, err := netlinksafe.LinkByName(iface)
	if err != nil {
		// If interface is not found by any reason it's safe to ignore an error. Also, we don't need to raise an error
		// during cmdDel call according to CNI spec:
		// https://github.com/containernetworking/cni/blob/main/SPEC.md#del-remove-container-from-network-or-un-apply-modifications
		_, notFound := err.(netlink.LinkNotFoundError)
		if notFound {
			return nil
		}
		log.Printf("Failed to get link %s: %v", iface, err)
		return fmt.Errorf("Failed to get link %s: %v", iface, err)
	}

	addrs, err := netlinksafe.AddrList(link, netlink.FAMILY_ALL)
	if err != nil {
		log.Printf("Failed to list all addrs: %v", err)
		return fmt.Errorf("Failed to list all addrs: %v", err)
	}

RULE_LOOP:
	for _, rule := range rules {
		log.Printf("Check rule: %v", rule)
		if rule.Src == nil {
			continue
		}

		for _, addr := range addrs {
			if rule.Src.IP.Equal(addr.IP) {
				log.Printf("Delete rule %v", rule)
				err := netlink.RuleDel(&rule)
				if err != nil {
					errReturn = fmt.Errorf("Failed to delete rule %v", err)
					log.Printf("... Failed! %v", err)
				}
				continue RULE_LOOP
			}
		}

	}

	return errReturn
}

func main() {
	skel.PluginMainFuncs(skel.CNIFuncs{
		Add:   cmdAdd,
		Check: cmdCheck,
		Del:   cmdDel,
		/* FIXME GC */
		/* FIXME Status */
	}, version.All, bv.BuildString("sbr"))
}

func cmdCheck(_ *skel.CmdArgs) error {
	return nil
}
