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

package main

import (
	"fmt"
	"log"
	"net"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/containernetworking/plugins/pkg/testutils"
)

// Structures specifying state at start.
type Device struct {
	Name   string
	Addrs  []net.IPNet
	Routes []netlink.Route
}

type Rule struct {
	Src   string
	Table int
}

type netStatus struct {
	Devices []Device
	Rules   []netlink.Rule
}

// Create a link, shove some IP addresses on it, and push it into the network
// namespace.
func setup(targetNs ns.NetNS, status netStatus) error {
	// Get the status right
	err := targetNs.Do(func(_ ns.NetNS) error {
		for _, dev := range status.Devices {
			log.Printf("Adding dev %s\n", dev.Name)
			linkAttrs := netlink.NewLinkAttrs()
			linkAttrs.Name = dev.Name
			link := &netlink.Dummy{LinkAttrs: linkAttrs}
			err := netlink.LinkAdd(link)
			if err != nil {
				return err
			}

			err = netlink.LinkSetUp(link)
			if err != nil {
				return err
			}

			for _, addr := range dev.Addrs {
				log.Printf("Adding address %v to device %s\n", addr, dev.Name)
				err = netlink.AddrAdd(link, &netlink.Addr{IPNet: &addr})
				if err != nil {
					return err
				}
			}

			for _, route := range dev.Routes {
				log.Printf("Adding route %v to device %s\n", route, dev.Name)
				route.LinkIndex = link.Attrs().Index
				err = netlink.RouteAdd(&route)
				if err != nil {
					return err
				}
			}
		}
		return nil
	})

	return err
}

// Readback the routes and rules.
func readback(targetNs ns.NetNS, devNames []string) (netStatus, error) {
	// Get the status right.
	var retVal netStatus

	err := targetNs.Do(func(_ ns.NetNS) error {
		retVal.Devices = make([]Device, 2)

		for i, name := range devNames {
			log.Printf("Checking device %s", name)
			retVal.Devices[i].Name = name

			link, err := netlink.LinkByName(name)
			if err != nil {
				return err
			}

			// Need to read all tables, so cannot use RouteList
			routeFilter := &netlink.Route{
				LinkIndex: link.Attrs().Index,
				Table:     unix.RT_TABLE_UNSPEC,
			}

			routes, err := netlink.RouteListFiltered(netlink.FAMILY_ALL,
				routeFilter,
				netlink.RT_FILTER_OIF|netlink.RT_FILTER_TABLE)
			if err != nil {
				return err
			}

			routesNoLinkLocal := []netlink.Route{}
			for _, route := range routes {
				if route.Dst.IP.IsLinkLocalMulticast() || route.Dst.IP.IsLinkLocalUnicast() {
					continue
				}
				log.Printf("Got %s route %v", name, route)
				routesNoLinkLocal = append(routesNoLinkLocal, route)
			}

			retVal.Devices[i].Routes = routesNoLinkLocal
		}

		rules, err := netlink.RuleList(netlink.FAMILY_ALL)
		if err != nil {
			return err
		}

		retVal.Rules = make([]netlink.Rule, 0, len(rules))

		for _, rule := range rules {
			// Rules over 250 are the kernel defaults, that we ignore.
			if rule.Table < 250 {
				log.Printf("Got interesting rule %v", rule)
				retVal.Rules = append(retVal.Rules, rule)
			}
		}

		return nil
	})

	return retVal, err
}

func equalRoutes(expected, actual []netlink.Route) bool {
	// Compare two sets of routes, comparing only destination, gateway and
	// table. Return true if equal.
	match := true

	// Map used to make comparisons easy
	expMap := make(map[string]bool)

	for _, route := range expected {
		expMap[route.String()] = true
	}

	for _, route := range actual {
		routeString := route.String()
		if expMap[routeString] {
			log.Printf("Route %s expected and found", routeString)
			delete(expMap, routeString)
		} else {
			log.Printf("Route %s found, not expected", routeString)
			match = false
		}
	}

	for expRoute := range expMap {
		log.Printf("Route %s expected, not found", expRoute)
		match = false
	}

	return match
}

func createDefaultStatus() netStatus {
	// Useful default status.
	devs := make([]Device, 2)
	rules := make([]netlink.Rule, 0)

	devs[0] = Device{Name: "eth0"}
	devs[0].Addrs = make([]net.IPNet, 1)
	devs[0].Addrs[0] = net.IPNet{
		IP:   net.IPv4(10, 0, 0, 2),
		Mask: net.IPv4Mask(255, 255, 255, 0),
	}
	devs[0].Routes = make([]netlink.Route, 2)
	devs[0].Routes[0] = netlink.Route{
		Dst: &net.IPNet{
			IP:   net.IPv4(10, 2, 0, 0),
			Mask: net.IPv4Mask(255, 255, 255, 0),
		},
		Gw: net.IPv4(10, 0, 0, 5),
	}
	devs[0].Routes[1] = netlink.Route{
		Gw: net.IPv4(10, 0, 0, 1),
	}

	devs[1] = Device{Name: "net1"}
	devs[1].Addrs = make([]net.IPNet, 1)
	devs[1].Addrs[0] = net.IPNet{
		IP:   net.IPv4(192, 168, 1, 209),
		Mask: net.IPv4Mask(255, 255, 255, 0),
	}
	devs[1].Routes = make([]netlink.Route, 1)
	devs[1].Routes[0] = netlink.Route{
		Dst: &net.IPNet{
			IP:   net.IPv4(192, 168, 2, 0),
			Mask: net.IPv4Mask(255, 255, 255, 0),
		},
		Gw: net.IPv4(192, 168, 1, 2),
	}

	return netStatus{
		Devices: devs,
		Rules:   rules,
	}
}

var _ = Describe("sbr test", func() {
	var targetNs ns.NetNS

	BeforeEach(func() {
		var err error
		targetNs, err = testutils.NewNS()
		Expect(err).NotTo(HaveOccurred())
	})

	AfterEach(func() {
		targetNs.Close()
	})

	It("Works with a 0.3.0 config", func() {
		ifname := "net1"
		conf := `{
	"cniVersion": "0.3.0",
	"name": "cni-plugin-sbr-test",
	"type": "sbr",
	"prevResult": {
		"cniVersion": "0.3.0",
		"interfaces": [
			{
				"name": "%s",
				"sandbox": "%s"
			}
		],
		"ips": [
			{
				"version": "4",
				"address": "192.168.1.209/24",
				"gateway": "192.168.1.1",
				"interface": 0
			}
		],
		"routes": []
	}
}`
		conf = fmt.Sprintf(conf, ifname, targetNs.Path())
		args := &skel.CmdArgs{
			ContainerID: "dummy",
			Netns:       targetNs.Path(),
			IfName:      ifname,
			StdinData:   []byte(conf),
		}

		err := setup(targetNs, createDefaultStatus())
		Expect(err).NotTo(HaveOccurred())

		oldStatus, err := readback(targetNs, []string{"net1", "eth0"})
		Expect(err).NotTo(HaveOccurred())

		_, _, err = testutils.CmdAddWithArgs(args, func() error { return cmdAdd(args) })
		Expect(err).NotTo(HaveOccurred())

		newStatus, err := readback(targetNs, []string{"net1", "eth0"})
		Expect(err).NotTo(HaveOccurred())

		// Check results. We expect all the routes on net1 to have moved to
		// table 100 except for local routes (table 255); a new default gateway
		// route to have been created; and a single rule to exist.
		expNet1 := oldStatus.Devices[0]
		expEth0 := oldStatus.Devices[1]
		for i := range expNet1.Routes {
			if expNet1.Routes[i].Table != 255 {
				expNet1.Routes[i].Table = 100
			}
		}
		expNet1.Routes = append(expNet1.Routes,
			netlink.Route{
				Gw:        net.IPv4(192, 168, 1, 1),
				Dst:       &net.IPNet{IP: net.IPv4zero, Mask: net.IPMask(net.IPv4zero)},
				Table:     100,
				LinkIndex: expNet1.Routes[0].LinkIndex,
			})

		Expect(newStatus.Rules).To(HaveLen(1))
		Expect(newStatus.Rules[0].Table).To(Equal(100))
		Expect(newStatus.Rules[0].Src.String()).To(Equal("192.168.1.209/32"))
		devNet1 := newStatus.Devices[0]
		devEth0 := newStatus.Devices[1]
		Expect(equalRoutes(expNet1.Routes, devNet1.Routes)).To(BeTrue())
		Expect(equalRoutes(expEth0.Routes, devEth0.Routes)).To(BeTrue())

		conf = `{
	"cniVersion": "0.3.0",
	"name": "cni-plugin-sbr-test",
	"type": "sbr"
}`

		// And now check that we can back it all out.
		args = &skel.CmdArgs{
			ContainerID: "dummy",
			Netns:       targetNs.Path(),
			IfName:      ifname,
			StdinData:   []byte(conf),
		}
		err = testutils.CmdDelWithArgs(args, func() error { return cmdDel(args) })
		Expect(err).NotTo(HaveOccurred())

		retVal, err := readback(targetNs, []string{"net1", "eth0"})
		Expect(err).NotTo(HaveOccurred())

		// Check results. We expect the rule to have been removed.
		Expect(retVal.Rules).To(BeEmpty())
	})

	It("Works with a default route already set", func() {
		ifname := "net1"
		conf := `{
	"cniVersion": "0.3.0",
	"name": "cni-plugin-sbr-test",
	"type": "sbr",
	"prevResult": {
		"cniVersion": "0.3.0",
		"interfaces": [
			{
				"name": "%s",
				"sandbox": "%s"
			}
		],
		"ips": [
			{
				"version": "4",
				"address": "192.168.1.209/24",
				"gateway": "192.168.1.1",
				"interface": 0
			}
		],
		"routes": []
	}
}`
		conf = fmt.Sprintf(conf, ifname, targetNs.Path())
		args := &skel.CmdArgs{
			ContainerID: "dummy",
			Netns:       targetNs.Path(),
			IfName:      ifname,
			StdinData:   []byte(conf),
		}

		preStatus := createDefaultStatus()
		// Remove final (default) route from eth0, then add another default
		// route to net1
		preStatus.Devices[0].Routes = preStatus.Devices[0].Routes[:0]
		routes := preStatus.Devices[1].Routes
		preStatus.Devices[1].Routes = append(preStatus.Devices[1].Routes,
			netlink.Route{
				Gw:        net.IPv4(192, 168, 1, 1),
				LinkIndex: routes[0].LinkIndex,
			})

		err := setup(targetNs, preStatus)
		Expect(err).NotTo(HaveOccurred())

		oldStatus, err := readback(targetNs, []string{"net1", "eth0"})
		Expect(err).NotTo(HaveOccurred())

		_, _, err = testutils.CmdAddWithArgs(args, func() error { return cmdAdd(args) })
		Expect(err).NotTo(HaveOccurred())

		newStatus, err := readback(targetNs, []string{"net1", "eth0"})
		Expect(err).NotTo(HaveOccurred())

		// Check results. We expect all the routes on net1 to have moved to
		// table 100 except for local routes (table 255); a new default gateway
		// route to have been created; and a single rule to exist.
		expNet1 := oldStatus.Devices[0]
		expEth0 := oldStatus.Devices[1]
		for i := range expNet1.Routes {
			if expNet1.Routes[i].Table != 255 {
				expNet1.Routes[i].Table = 100
			}
		}

		Expect(newStatus.Rules).To(HaveLen(1))
		Expect(newStatus.Rules[0].Table).To(Equal(100))
		Expect(newStatus.Rules[0].Src.String()).To(Equal("192.168.1.209/32"))
		devNet1 := newStatus.Devices[0]
		devEth0 := newStatus.Devices[1]
		Expect(equalRoutes(expEth0.Routes, devEth0.Routes)).To(BeTrue())
		Expect(equalRoutes(expNet1.Routes, devNet1.Routes)).To(BeTrue())
	})

	It("Works with multiple IPs", func() {
		ifname := "net1"
		conf := `{
	"cniVersion": "0.3.0",
	"name": "cni-plugin-sbr-test",
	"type": "sbr",
	"prevResult": {
		"cniVersion": "0.3.0",
		"interfaces": [
			{
				"name": "%s",
				"sandbox": "%s"
			}
		],
		"ips": [
			{
				"version": "4",
				"address": "192.168.1.209/24",
				"gateway": "192.168.1.1",
				"interface": 0
			},
			{
				"version": "4",
				"address": "192.168.101.209/24",
				"gateway": "192.168.101.1",
				"interface": 1
			}
		],
		"routes": []
	}
}`
		conf = fmt.Sprintf(conf, ifname, targetNs.Path())
		args := &skel.CmdArgs{
			ContainerID: "dummy",
			Netns:       targetNs.Path(),
			IfName:      ifname,
			StdinData:   []byte(conf),
		}

		preStatus := createDefaultStatus()

		// Add the second IP on net1 interface
		preStatus.Devices[1].Addrs = append(preStatus.Devices[1].Addrs,
			net.IPNet{
				IP:   net.IPv4(192, 168, 101, 209),
				Mask: net.IPv4Mask(255, 255, 255, 0),
			})

		err := setup(targetNs, preStatus)
		Expect(err).NotTo(HaveOccurred())

		oldStatus, err := readback(targetNs, []string{"net1", "eth0"})
		Expect(err).NotTo(HaveOccurred())

		_, _, err = testutils.CmdAddWithArgs(args, func() error { return cmdAdd(args) })
		Expect(err).NotTo(HaveOccurred())

		newStatus, err := readback(targetNs, []string{"net1", "eth0"})
		Expect(err).NotTo(HaveOccurred())

		// Check results. We expect all the routes on net1 to have moved to
		// table 100 except for local routes (table 255); a new default gateway
		// route to have been created; and 2 rules to exist.
		expNet1 := oldStatus.Devices[0]
		expEth0 := oldStatus.Devices[1]

		for i := range expNet1.Routes {
			if expNet1.Routes[i].Table != 255 {
				if expNet1.Routes[i].Src.String() == "192.168.101.209" {
					// All 192.168.101.x routes expected in table 101
					expNet1.Routes[i].Table = 101
				} else if expNet1.Routes[i].Src == nil && expNet1.Routes[i].Gw == nil {
					// Generic Link Local Addresses assigned. They should exist in all
					// route tables
					expNet1.Routes[i].Table = 100
					expNet1.Routes = append(expNet1.Routes,
						netlink.Route{
							Dst:       expNet1.Routes[i].Dst,
							Table:     101,
							LinkIndex: expNet1.Routes[i].LinkIndex,
						})
				} else {
					// All 192.168.1.x routes expected in table 100
					expNet1.Routes[i].Table = 100
				}
			}
		}
		expNet1.Routes = append(expNet1.Routes,
			netlink.Route{
				Dst:       &net.IPNet{IP: net.IPv4zero, Mask: net.IPMask(net.IPv4zero)},
				Gw:        net.IPv4(192, 168, 1, 1),
				Table:     100,
				LinkIndex: expNet1.Routes[0].LinkIndex,
			})

		expNet1.Routes = append(expNet1.Routes,
			netlink.Route{
				Dst:       &net.IPNet{IP: net.IPv4zero, Mask: net.IPMask(net.IPv4zero)},
				Gw:        net.IPv4(192, 168, 101, 1),
				Table:     101,
				LinkIndex: expNet1.Routes[0].LinkIndex,
			})

		// 2 Rules will be created for each IP address. (100, 101)
		Expect(newStatus.Rules).To(HaveLen(2))

		// First entry corresponds to last table
		Expect(newStatus.Rules[0].Table).To(Equal(101))
		Expect(newStatus.Rules[0].Src.String()).To(Equal("192.168.101.209/32"))

		// Second entry corresponds to first table (100)
		Expect(newStatus.Rules[1].Table).To(Equal(100))
		Expect(newStatus.Rules[1].Src.String()).To(Equal("192.168.1.209/32"))

		devNet1 := newStatus.Devices[0]
		devEth0 := newStatus.Devices[1]
		Expect(equalRoutes(expNet1.Routes, devNet1.Routes)).To(BeTrue())
		Expect(equalRoutes(expEth0.Routes, devEth0.Routes)).To(BeTrue())
	})

	It("fails with CNI spec versions that don't support plugin chaining", func() {
		conf := `{
	"cniVersion": "0.2.0",
	"name": "cni-plugin-sbr-test",
	"type": "sbr",
	"anotherAwesomeArg": "foo"
}`

		args := &skel.CmdArgs{
			ContainerID: "dummy",
			Netns:       targetNs.Path(),
			IfName:      "net1",
			StdinData:   []byte(conf),
		}
		err := setup(targetNs, createDefaultStatus())
		Expect(err).NotTo(HaveOccurred())

		_, _, err = testutils.CmdAddWithArgs(args, func() error { return cmdAdd(args) })
		Expect(err).To(MatchError("This plugin must be called as chained plugin"))
	})

	It("Works with Table ID", func() {
		ifname := "net1"
		tableID := 5000
		conf := `{
	"cniVersion": "0.3.0",
	"name": "cni-plugin-sbr-test",
	"type": "sbr",
	"table": %d,
	"prevResult": {
		"cniVersion": "0.3.0",
		"interfaces": [
			{
				"name": "%s",
				"sandbox": "%s"
			}
		],
		"ips": [
			{
				"address": "192.168.1.209/24",
				"interface": 0
			},
			{
				"address": "192.168.101.209/24",
				"interface": 0
			}
		],
		"routes": []
	}
}`
		conf = fmt.Sprintf(conf, tableID, ifname, targetNs.Path())
		args := &skel.CmdArgs{
			ContainerID: "dummy",
			Netns:       targetNs.Path(),
			IfName:      ifname,
			StdinData:   []byte(conf),
		}

		preStatus := createDefaultStatus()

		err := setup(targetNs, preStatus)
		Expect(err).NotTo(HaveOccurred())

		oldStatus, err := readback(targetNs, []string{"net1", "eth0"})
		Expect(err).NotTo(HaveOccurred())

		_, _, err = testutils.CmdAddWithArgs(args, func() error { return cmdAdd(args) })
		Expect(err).NotTo(HaveOccurred())

		newStatus, err := readback(targetNs, []string{"net1", "eth0"})
		Expect(err).NotTo(HaveOccurred())

		// Routes have not been moved.
		Expect(newStatus).To(Equal(oldStatus))

		// Fetch all rules for the requested table ID.
		var rules []netlink.Rule
		err = targetNs.Do(func(_ ns.NetNS) error {
			var err error
			rules, err = netlink.RuleListFiltered(
				netlink.FAMILY_ALL, &netlink.Rule{
					Table: tableID,
				},
				netlink.RT_FILTER_TABLE,
			)
			return err
		})

		Expect(err).NotTo(HaveOccurred())
		Expect(rules).To(HaveLen(2))

		// Both IPs have been added as source based routes with requested table ID.
		Expect(rules[0].Table).To(Equal(tableID))
		Expect(rules[0].Src.String()).To(Equal("192.168.101.209/32"))
		Expect(rules[1].Table).To(Equal(tableID))
		Expect(rules[1].Src.String()).To(Equal("192.168.1.209/32"))
	})
})
