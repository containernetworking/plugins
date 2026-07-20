// Copyright 2020 CNI authors
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
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/vishvananda/netlink"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	current "github.com/containernetworking/cni/pkg/types/100"
	"github.com/containernetworking/plugins/pkg/netlinksafe"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/containernetworking/plugins/pkg/testutils"
)

func buildOneConfig(name, cniVersion string, orig *VRFNetConf, prevResult types.Result) (*VRFNetConf, []byte, error) {
	var err error

	inject := map[string]interface{}{
		"name":       name,
		"cniVersion": cniVersion,
	}
	// Add previous plugin result
	if prevResult != nil {
		inject["prevResult"] = prevResult
	}

	// Ensure every config uses the same name and version
	config := make(map[string]interface{})

	confBytes, err := json.Marshal(*orig)
	if err != nil {
		return nil, nil, err
	}

	err = json.Unmarshal(confBytes, &config)
	if err != nil {
		return nil, nil, fmt.Errorf("unmarshal existing network bytes: %s", err)
	}

	for key, value := range inject {
		config[key] = value
	}

	newBytes, err := json.Marshal(config)
	if err != nil {
		return nil, nil, err
	}

	conf := &VRFNetConf{}
	if err := json.Unmarshal(newBytes, &conf); err != nil {
		return nil, nil, fmt.Errorf("error parsing configuration: %s", err)
	}

	return conf, newBytes, nil
}

var _ = Describe("vrf plugin", func() {
	var originalNS ns.NetNS
	var targetNS ns.NetNS
	const (
		IF0Name  = "dummy0"
		IF1Name  = "dummy1"
		VRF0Name = "vrf0"
		VRF1Name = "vrf1"
	)

	BeforeEach(func() {
		var err error
		originalNS, err = testutils.NewNS()
		Expect(err).NotTo(HaveOccurred())

		targetNS, err = testutils.NewNS()
		Expect(err).NotTo(HaveOccurred())

		err = targetNS.Do(func(ns.NetNS) error {
			defer GinkgoRecover()

			la0 := netlink.NewLinkAttrs()
			la0.Name = IF0Name
			err = netlink.LinkAdd(&netlink.Dummy{
				LinkAttrs: la0,
			})
			Expect(err).NotTo(HaveOccurred())
			_, err = netlinksafe.LinkByName(IF0Name)
			Expect(err).NotTo(HaveOccurred())

			la1 := netlink.NewLinkAttrs()
			la1.Name = IF1Name
			err = netlink.LinkAdd(&netlink.Dummy{
				LinkAttrs: la1,
			})
			Expect(err).NotTo(HaveOccurred())
			_, err = netlinksafe.LinkByName(IF1Name)
			Expect(err).NotTo(HaveOccurred())
			return nil
		})
		Expect(err).NotTo(HaveOccurred())
	})

	AfterEach(func() {
		Expect(originalNS.Close()).To(Succeed())
		Expect(targetNS.Close()).To(Succeed())
	})

	It("passes prevResult through unchanged", func() {
		conf := configFor("test", IF0Name, VRF0Name, "10.0.0.2/24")

		args := &skel.CmdArgs{
			ContainerID: "dummy",
			Netns:       targetNS.Path(),
			IfName:      IF0Name,
			StdinData:   conf,
		}

		err := originalNS.Do(func(ns.NetNS) error {
			defer GinkgoRecover()

			r, _, err := testutils.CmdAddWithArgs(args, func() error {
				return cmdAdd(args)
			})
			Expect(err).NotTo(HaveOccurred())

			result, err := current.GetResult(r)
			Expect(err).NotTo(HaveOccurred())

			Expect(result.Interfaces).To(HaveLen(1))
			Expect(result.Interfaces[0].Name).To(Equal(IF0Name))
			Expect(result.IPs).To(HaveLen(1))
			Expect(result.IPs[0].Address.String()).To(Equal("10.0.0.2/24"))
			return nil
		})
		Expect(err).NotTo(HaveOccurred())
	})

	It("configures a VRF and adds the interface to it", func() {
		conf := configFor("test", IF0Name, VRF0Name, "10.0.0.2/24")

		args := &skel.CmdArgs{
			ContainerID: "dummy",
			Netns:       targetNS.Path(),
			IfName:      IF0Name,
			StdinData:   conf,
		}

		err := originalNS.Do(func(ns.NetNS) error {
			defer GinkgoRecover()
			_, _, err := testutils.CmdAddWithArgs(args, func() error {
				return cmdAdd(args)
			})
			Expect(err).NotTo(HaveOccurred())
			return nil
		})
		Expect(err).NotTo(HaveOccurred())

		err = targetNS.Do(func(ns.NetNS) error {
			defer GinkgoRecover()
			checkInterfaceOnVRF(VRF0Name, IF0Name)
			return nil
		})
		Expect(err).NotTo(HaveOccurred())
	})

	It("adds the interface and custom routing to new VRF", func() {
		conf := configWithRouteFor("test", IF0Name, VRF0Name, "10.0.0.2/24", "10.10.10.0/24")

		By("Setting custom routing first", func() {
			err := targetNS.Do(func(ns.NetNS) error {
				defer GinkgoRecover()

				ipv4, err := types.ParseCIDR("10.0.0.2/24")
				Expect(err).NotTo(HaveOccurred())
				Expect(ipv4).NotTo(BeNil())

				_, routev4, err := net.ParseCIDR("10.10.10.0/24")
				Expect(err).NotTo(HaveOccurred())

				ipv6, err := types.ParseCIDR("abcd:1234:ffff::cdde/64")
				Expect(err).NotTo(HaveOccurred())
				Expect(ipv6).NotTo(BeNil())

				_, routev6, err := net.ParseCIDR("1111:dddd::/80")
				Expect(err).NotTo(HaveOccurred())
				Expect(routev6).NotTo(BeNil())

				link, err := netlinksafe.LinkByName(IF0Name)
				Expect(err).NotTo(HaveOccurred())

				// Add IP addresses for network reachability
				netlink.AddrAdd(link, &netlink.Addr{IPNet: ipv4})
				netlink.AddrAdd(link, &netlink.Addr{IPNet: ipv6})
				// Wait for the corresponding route to be addeded
				Eventually(func() bool {
					ipv6RouteDst := &net.IPNet{
						IP:   ipv6.IP,
						Mask: net.IPMask{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
					}
					routes, _ := netlinksafe.RouteListFiltered(netlink.FAMILY_ALL, &netlink.Route{
						Dst:   ipv6RouteDst,
						Table: 0,
					}, netlink.RT_FILTER_DST|netlink.RT_FILTER_TABLE)
					return err == nil && len(routes) >= 1
				}, time.Second, 500*time.Millisecond).Should(BeTrue())

				ipAddrs, err := netlinksafe.AddrList(link, netlink.FAMILY_V4)
				Expect(err).NotTo(HaveOccurred())
				// Check if address was assigned properly
				Expect(ipAddrs[0].IP.String()).To(Equal("10.0.0.2"))

				// Set interface UP, otherwise local route to 10.0.0.0/24 is not present
				err = netlink.LinkSetUp(link)
				Expect(err).NotTo(HaveOccurred())

				// Add additional route to 10.10.10.0/24 via 10.0.0.1 gateway
				r := netlink.Route{
					LinkIndex: link.Attrs().Index,
					Src:       ipv4.IP,
					Dst:       routev4,
					Gw:        net.ParseIP("10.0.0.1"),
				}
				err = netlink.RouteAdd(&r)
				Expect(err).NotTo(HaveOccurred())

				r6 := netlink.Route{
					LinkIndex: link.Attrs().Index,
					Src:       ipv6.IP,
					Dst:       routev6,
					Gw:        net.ParseIP("abcd:1234:ffff::1"),
				}
				err = netlink.RouteAdd(&r6)
				Expect(err).NotTo(HaveOccurred())

				return nil
			})
			Expect(err).NotTo(HaveOccurred())
		})

		args := &skel.CmdArgs{
			ContainerID: "dummy",
			Netns:       targetNS.Path(),
			IfName:      IF0Name,
			StdinData:   conf,
		}

		err := originalNS.Do(func(ns.NetNS) error {
			defer GinkgoRecover()
			r, _, err := testutils.CmdAddWithArgs(args, func() error {
				return cmdAdd(args)
			})
			Expect(err).NotTo(HaveOccurred())

			result, err := current.GetResult(r)
			Expect(err).NotTo(HaveOccurred())

			Expect(result.Interfaces).To(HaveLen(1))
			Expect(result.Interfaces[0].Name).To(Equal(IF0Name))
			Expect(result.Routes).To(HaveLen(1))
			Expect(result.Routes[0].Dst.IP.String()).To(Equal("10.10.10.0"))
			return nil
		})
		Expect(err).NotTo(HaveOccurred())

		err = targetNS.Do(func(ns.NetNS) error {
			defer GinkgoRecover()
			checkInterfaceOnVRF(VRF0Name, IF0Name)
			checkRoutesOnVRF(VRF0Name, IF0Name, "10.0.0.2", "10.10.10.0/24", "1111:dddd::/80")
			return nil
		})
		Expect(err).NotTo(HaveOccurred())
	})

	It("filters the correct routes to import to new VRF", func() {
		_ = configWithRouteFor("test0", IF0Name, VRF0Name, "10.0.0.2/24", "10.10.10.0/24")
		conf1 := configWithRouteFor("test1", IF1Name, VRF1Name, "10.0.0.3/24", "10.11.10.0/24")

		By("Setting custom routing for IF0Name", func() {
			err := targetNS.Do(func(ns.NetNS) error {
				defer GinkgoRecover()

				ipv4, err := types.ParseCIDR("10.0.0.2/24")
				Expect(err).NotTo(HaveOccurred())
				Expect(ipv4).NotTo(BeNil())

				_, routev4, err := net.ParseCIDR("10.10.10.0/24")
				Expect(err).NotTo(HaveOccurred())

				ipv6, err := types.ParseCIDR("abcd:1234:ffff::cdde/64")
				Expect(err).NotTo(HaveOccurred())
				Expect(ipv6).NotTo(BeNil())

				_, routev6, err := net.ParseCIDR("1111:dddd::/80")
				Expect(err).NotTo(HaveOccurred())
				Expect(routev6).NotTo(BeNil())

				link, err := netlinksafe.LinkByName(IF0Name)
				Expect(err).NotTo(HaveOccurred())

				// Add IP addresses for network reachability
				netlink.AddrAdd(link, &netlink.Addr{IPNet: ipv4})
				netlink.AddrAdd(link, &netlink.Addr{IPNet: ipv6})
				// Wait for the corresponding route to be addeded
				Eventually(func() bool {
					ipv6RouteDst := &net.IPNet{
						IP:   ipv6.IP,
						Mask: net.IPMask{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
					}
					routes, _ := netlinksafe.RouteListFiltered(netlink.FAMILY_ALL, &netlink.Route{
						Dst:   ipv6RouteDst,
						Table: 0,
					}, netlink.RT_FILTER_DST|netlink.RT_FILTER_TABLE)
					return err == nil && len(routes) >= 1
				}, time.Second, 500*time.Millisecond).Should(BeTrue())

				ipAddrs, err := netlinksafe.AddrList(link, netlink.FAMILY_V4)
				Expect(err).NotTo(HaveOccurred())
				// Check if address was assigned properly
				Expect(ipAddrs[0].IP.String()).To(Equal("10.0.0.2"))

				// Set interface UP, otherwise local route to 10.0.0.0/24 is not present
				err = netlink.LinkSetUp(link)
				Expect(err).NotTo(HaveOccurred())

				// Add additional route to 10.10.10.0/24 via 10.0.0.1 gateway
				r := netlink.Route{
					LinkIndex: link.Attrs().Index,
					Dst:       routev4,
					Gw:        net.ParseIP("10.0.0.1"),
				}
				err = netlink.RouteAdd(&r)
				Expect(err).NotTo(HaveOccurred())

				r6 := netlink.Route{
					LinkIndex: link.Attrs().Index,
					Src:       ipv6.IP,
					Dst:       routev6,
					Gw:        net.ParseIP("abcd:1234:ffff::1"),
				}
				err = netlink.RouteAdd(&r6)
				Expect(err).NotTo(HaveOccurred())

				return nil
			})
			Expect(err).NotTo(HaveOccurred())
		})

		By("Setting custom routing for IF1Name", func() {
			err := targetNS.Do(func(ns.NetNS) error {
				defer GinkgoRecover()

				ipv4, err := types.ParseCIDR("10.0.0.3/24")
				Expect(err).NotTo(HaveOccurred())
				Expect(ipv4).NotTo(BeNil())

				_, routev4, err := net.ParseCIDR("10.11.10.0/24")
				Expect(err).NotTo(HaveOccurred())

				ipv6, err := types.ParseCIDR("abcd:1234:ffff::cddf/64")
				Expect(err).NotTo(HaveOccurred())
				Expect(ipv6).NotTo(BeNil())

				_, routev6, err := net.ParseCIDR("1111:ddde::/80")
				Expect(err).NotTo(HaveOccurred())
				Expect(routev6).NotTo(BeNil())

				link, err := netlinksafe.LinkByName(IF1Name)
				Expect(err).NotTo(HaveOccurred())

				// Add IP addresses for network reachability
				netlink.AddrAdd(link, &netlink.Addr{IPNet: ipv4})
				netlink.AddrAdd(link, &netlink.Addr{IPNet: ipv6})
				// Wait for the corresponding route to be addeded
				Eventually(func() bool {
					ipv6RouteDst := &net.IPNet{
						IP:   ipv6.IP,
						Mask: net.IPMask{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
					}
					routes, _ := netlinksafe.RouteListFiltered(netlink.FAMILY_ALL, &netlink.Route{
						Dst:   ipv6RouteDst,
						Table: 0,
					}, netlink.RT_FILTER_DST|netlink.RT_FILTER_TABLE)
					return err == nil && len(routes) >= 1
				}, time.Second, 500*time.Millisecond).Should(BeTrue())

				ipAddrs, err := netlinksafe.AddrList(link, netlink.FAMILY_V4)
				Expect(err).NotTo(HaveOccurred())
				// Check if address was assigned properly
				Expect(ipAddrs[0].IP.String()).To(Equal("10.0.0.3"))

				// Set interface UP, otherwise local route to 10.0.0.0/24 is not present
				err = netlink.LinkSetUp(link)
				Expect(err).NotTo(HaveOccurred())

				// Add additional route to 10.11.10.0/24 via 10.0.0.1 gateway
				r := netlink.Route{
					LinkIndex: link.Attrs().Index,
					Src:       ipv4.IP,
					Dst:       routev4,
					Gw:        net.ParseIP("10.0.0.1"),
					Priority:  100,
				}
				err = netlink.RouteAdd(&r)
				Expect(err).NotTo(HaveOccurred())

				r6 := netlink.Route{
					LinkIndex: link.Attrs().Index,
					Src:       ipv6.IP,
					Dst:       routev6,
					Gw:        net.ParseIP("abcd:1234:ffff::1"),
				}
				err = netlink.RouteAdd(&r6)
				Expect(err).NotTo(HaveOccurred())

				return nil
			})
			Expect(err).NotTo(HaveOccurred())
		})

		By("Adding if1 to the VRF", func() {
			err := originalNS.Do(func(ns.NetNS) error {
				defer GinkgoRecover()

				args := &skel.CmdArgs{
					ContainerID: "dummy",
					Netns:       targetNS.Path(),
					IfName:      IF1Name,
					StdinData:   conf1,
				}
				_, _, err := testutils.CmdAddWithArgs(args, func() error {
					return cmdAdd(args)
				})
				Expect(err).NotTo(HaveOccurred())

				return nil
			})
			Expect(err).NotTo(HaveOccurred())
		})

		By("Checking routes are moved correctly to VRF", func() {
			err := targetNS.Do(func(ns.NetNS) error {
				defer GinkgoRecover()

				checkInterfaceOnVRF(VRF1Name, IF1Name)
				checkRoutesOnVRF(VRF1Name, IF1Name, "10.0.0.3", "10.11.10.0/24", "1111:ddde::/80")

				return nil
			})
			Expect(err).NotTo(HaveOccurred())
		})
	})

	It("moves IPv6 ECMP default nexthop into the VRF table", func() {
		// Reproduce #1253: primary interface already has ::/0, IPAM adds another
		// ::/0 via the secondary interface, kernel merges them into multipath.
		// VRF must still move only the secondary nexthop into the VRF table.
		conf := configFor("test", IF1Name, VRF0Name, "10.0.0.2/24")

		By("Creating an IPv6 ECMP default route spanning both interfaces", func() {
			err := targetNS.Do(func(ns.NetNS) error {
				defer GinkgoRecover()

				link0, err := netlinksafe.LinkByName(IF0Name)
				Expect(err).NotTo(HaveOccurred())
				link1, err := netlinksafe.LinkByName(IF1Name)
				Expect(err).NotTo(HaveOccurred())

				addr0, err := types.ParseCIDR("2001:db8:0::2/64")
				Expect(err).NotTo(HaveOccurred())
				addr1, err := types.ParseCIDR("2001:db8:1::2/64")
				Expect(err).NotTo(HaveOccurred())

				Expect(netlink.AddrAdd(link0, &netlink.Addr{IPNet: addr0})).To(Succeed())
				Expect(netlink.AddrAdd(link1, &netlink.Addr{IPNet: addr1})).To(Succeed())
				Expect(netlink.LinkSetUp(link0)).To(Succeed())
				Expect(netlink.LinkSetUp(link1)).To(Succeed())

				// Wait for kernel host routes for the IPv6 addresses.
				Eventually(func() bool {
					routes, _ := netlinksafe.RouteListFiltered(netlink.FAMILY_V6, &netlink.Route{
						Dst: &net.IPNet{
							IP:   addr1.IP,
							Mask: net.CIDRMask(128, 128),
						},
						Table: 0,
					}, netlink.RT_FILTER_DST|netlink.RT_FILTER_TABLE)
					return len(routes) >= 1
				}, time.Second, 100*time.Millisecond).Should(BeTrue())

				defaultDst := &net.IPNet{
					IP:   net.IPv6zero,
					Mask: net.CIDRMask(0, 128),
				}
				// Install multipath default explicitly. Two sequential RouteAdd
				// calls with the same metric return EEXIST on some kernels
				// instead of merging into ECMP (repro path from #1253).
				Expect(netlink.RouteAdd(&netlink.Route{
					Dst:      defaultDst,
					Priority: 1024,
					MultiPath: []*netlink.NexthopInfo{
						{LinkIndex: link0.Attrs().Index, Gw: net.ParseIP("2001:db8:0::1")},
						{LinkIndex: link1.Attrs().Index, Gw: net.ParseIP("2001:db8:1::1")},
					},
				})).To(Succeed())

				// Confirm the kernel has a multipath default including both ifaces.
				routes, err := netlinksafe.RouteListFiltered(netlink.FAMILY_V6, &netlink.Route{
					Dst:   defaultDst,
					Table: 0,
				}, netlink.RT_FILTER_DST|netlink.RT_FILTER_TABLE)
				Expect(err).NotTo(HaveOccurred())
				Expect(routes).NotTo(BeEmpty())
				// Either a multipath route or two separate defaults (depends on kernel);
				// at least one must reference the secondary interface.
				hasIF1 := false
				for _, r := range routes {
					if r.LinkIndex == link1.Attrs().Index {
						hasIF1 = true
					}
					for _, nh := range r.MultiPath {
						if nh.LinkIndex == link1.Attrs().Index {
							hasIF1 = true
						}
					}
				}
				Expect(hasIF1).To(BeTrue(), "expected a default route nexthop on %s", IF1Name)
				return nil
			})
			Expect(err).NotTo(HaveOccurred())
		})

		By("Adding the secondary interface to the VRF", func() {
			err := originalNS.Do(func(ns.NetNS) error {
				defer GinkgoRecover()
				args := &skel.CmdArgs{
					ContainerID: "dummy",
					Netns:       targetNS.Path(),
					IfName:      IF1Name,
					StdinData:   conf,
				}
				_, _, err := testutils.CmdAddWithArgs(args, func() error {
					return cmdAdd(args)
				})
				Expect(err).NotTo(HaveOccurred())
				return nil
			})
			Expect(err).NotTo(HaveOccurred())
		})

		By("Checking the IPv6 default via the secondary interface is in the VRF table", func() {
			err := targetNS.Do(func(ns.NetNS) error {
				defer GinkgoRecover()
				checkInterfaceOnVRF(VRF0Name, IF1Name)

				vrfLink, err := netlinksafe.LinkByName(VRF0Name)
				Expect(err).NotTo(HaveOccurred())
				vrf := vrfLink.(*netlink.Vrf)
				link1, err := netlinksafe.LinkByName(IF1Name)
				Expect(err).NotTo(HaveOccurred())

				defaultDst := &net.IPNet{
					IP:   net.IPv6zero,
					Mask: net.CIDRMask(0, 128),
				}
				routes, err := netlinksafe.RouteListFiltered(netlink.FAMILY_V6, &netlink.Route{
					Dst:   defaultDst,
					Table: int(vrf.Table),
				}, netlink.RT_FILTER_DST|netlink.RT_FILTER_TABLE)
				Expect(err).NotTo(HaveOccurred())
				Expect(routes).NotTo(BeEmpty(), "expected ::/0 in VRF table %d", vrf.Table)

				found := false
				for _, r := range routes {
					if r.LinkIndex == link1.Attrs().Index && r.Gw.Equal(net.ParseIP("2001:db8:1::1")) {
						found = true
					}
					for _, nh := range r.MultiPath {
						if nh.LinkIndex == link1.Attrs().Index && nh.Gw.Equal(net.ParseIP("2001:db8:1::1")) {
							found = true
						}
					}
				}
				Expect(found).To(BeTrue(), "expected ::/0 via 2001:db8:1::1 dev %s in VRF table", IF1Name)
				return nil
			})
			Expect(err).NotTo(HaveOccurred())
		})
	})

	It("fails if the interface already has a master set", func() {
		conf := configFor("test", IF0Name, VRF0Name, "10.0.0.2/24")

		By("Setting the interface's master", func() {
			err := targetNS.Do(func(ns.NetNS) error {
				defer GinkgoRecover()
				l, err := netlinksafe.LinkByName(IF0Name)
				Expect(err).NotTo(HaveOccurred())
				linkAttrs := netlink.NewLinkAttrs()
				linkAttrs.Name = "testrbridge"
				br := &netlink.Bridge{
					LinkAttrs: linkAttrs,
				}
				err = netlink.LinkAdd(br)
				Expect(err).NotTo(HaveOccurred())
				err = netlink.LinkSetMaster(l, br)
				Expect(err).NotTo(HaveOccurred())
				return nil
			})
			Expect(err).NotTo(HaveOccurred())
		})

		args := &skel.CmdArgs{
			ContainerID: "dummy",
			Netns:       targetNS.Path(),
			IfName:      IF0Name,
			StdinData:   conf,
		}

		err := originalNS.Do(func(ns.NetNS) error {
			defer GinkgoRecover()
			_, _, err := testutils.CmdAddWithArgs(args, func() error {
				return cmdAdd(args)
			})
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("has already a master set"))
			return nil
		})
		Expect(err).NotTo(HaveOccurred())
	})

	DescribeTable("handles two interfaces",
		func(vrf0, vrf1, ip0, ip1 string) {
			conf0 := configFor("test", IF0Name, vrf0, ip0)
			conf1 := configFor("test1", IF1Name, vrf1, ip1)

			addr0, err := netlink.ParseAddr(ip0)
			Expect(err).NotTo(HaveOccurred())
			addr1, err := netlink.ParseAddr(ip1)
			Expect(err).NotTo(HaveOccurred())

			By("Setting the first interface's ip", func() {
				err := targetNS.Do(func(ns.NetNS) error {
					l, err := netlinksafe.LinkByName(IF0Name)
					Expect(err).NotTo(HaveOccurred())

					err = netlink.AddrAdd(l, addr0)
					Expect(err).NotTo(HaveOccurred())

					return nil
				})
				Expect(err).NotTo(HaveOccurred())
			})

			By("Adding the first interface to first vrf", func() {
				err := originalNS.Do(func(ns.NetNS) error {
					defer GinkgoRecover()
					args := &skel.CmdArgs{
						ContainerID: "dummy",
						Netns:       targetNS.Path(),
						IfName:      IF0Name,
						StdinData:   conf0,
					}
					_, _, err := testutils.CmdAddWithArgs(args, func() error {
						return cmdAdd(args)
					})
					Expect(err).NotTo(HaveOccurred())
					return nil
				})
				Expect(err).NotTo(HaveOccurred())
			})

			By("Setting the second interface's ip", func() {
				err := targetNS.Do(func(ns.NetNS) error {
					l, err := netlinksafe.LinkByName(IF1Name)
					Expect(err).NotTo(HaveOccurred())

					err = netlink.AddrAdd(l, addr1)
					Expect(err).NotTo(HaveOccurred())
					return nil
				})
				Expect(err).NotTo(HaveOccurred())
			})

			By("Adding the second interface to second vrf", func() {
				err := originalNS.Do(func(ns.NetNS) error {
					defer GinkgoRecover()
					args := &skel.CmdArgs{
						ContainerID: "dummy",
						Netns:       targetNS.Path(),
						IfName:      IF1Name,
						StdinData:   conf1,
					}
					_, _, err := testutils.CmdAddWithArgs(args, func() error {
						return cmdAdd(args)
					})
					Expect(err).NotTo(HaveOccurred())
					return nil
				})
				Expect(err).NotTo(HaveOccurred())
			})

			By("Checking that the first interface is added to first vrf", func() {
				err := targetNS.Do(func(ns.NetNS) error {
					defer GinkgoRecover()
					checkInterfaceOnVRF(vrf0, IF0Name)

					link, err := netlinksafe.LinkByName(IF0Name)
					Expect(err).NotTo(HaveOccurred())
					addresses, err := netlinksafe.AddrList(link, netlink.FAMILY_ALL)
					Expect(err).NotTo(HaveOccurred())
					Expect(addresses).To(HaveLen(1))
					Expect(addresses[0].IP.Equal(addr0.IP)).To(BeTrue())
					Expect(addresses[0].Mask).To(Equal(addr0.Mask))
					return nil
				})
				Expect(err).NotTo(HaveOccurred())
			})

			By("Checking that the second interface is added to second vrf", func() {
				err := targetNS.Do(func(ns.NetNS) error {
					defer GinkgoRecover()
					checkInterfaceOnVRF(vrf0, IF0Name)

					link, err := netlinksafe.LinkByName(IF1Name)
					Expect(err).NotTo(HaveOccurred())

					addresses, err := netlinksafe.AddrList(link, netlink.FAMILY_ALL)
					Expect(err).NotTo(HaveOccurred())
					Expect(addresses).To(HaveLen(1))
					Expect(addresses[0].IP.Equal(addr1.IP)).To(BeTrue())
					Expect(addresses[0].Mask).To(Equal(addr1.Mask))
					return nil
				})
				Expect(err).NotTo(HaveOccurred())
			})

			By("Checking that when the vrfs are different, the routing table is different", func() {
				if vrf0 == vrf1 {
					return
				}
				err := targetNS.Do(func(ns.NetNS) error {
					defer GinkgoRecover()
					l0, err := netlinksafe.LinkByName(vrf0)
					Expect(err).NotTo(HaveOccurred())
					Expect(l0).To(BeAssignableToTypeOf(&netlink.Vrf{}))
					l1, err := netlinksafe.LinkByName(vrf1)
					Expect(err).NotTo(HaveOccurred())
					Expect(l1).To(BeAssignableToTypeOf(&netlink.Vrf{}))

					vrf0Link := l0.(*netlink.Vrf)
					vrf1Link := l1.(*netlink.Vrf)
					Expect(vrf0Link.Table).NotTo(Equal(vrf1Link.Table))
					return nil
				})
				Expect(err).NotTo(HaveOccurred())
			})
		},
		Entry("added to the same vrf", VRF0Name, VRF0Name, "10.0.0.2/24", "10.0.0.3/24"),
		Entry("added to different vrfs", VRF0Name, VRF1Name, "10.0.0.2/24", "10.0.0.3/24"),
		Entry("added to different vrfs with same ip", VRF0Name, VRF1Name, "10.0.0.2/24", "10.0.0.2/24"),
		Entry("added to the same vrf IPV6", VRF0Name, VRF0Name, "2A00:0C98:2060:A000:0001:0000:1d1e:ca75/64", "2A00:0C98:2060:A000:0001:0000:1d1e:ca76/64"),
		Entry("added to different vrfs IPV6", VRF0Name, VRF1Name, "2A00:0C98:2060:A000:0001:0000:1d1e:ca75/64", "2A00:0C98:2060:A000:0001:0000:1d1e:ca76/64"),
		Entry("added to different vrfs with same ip IPV6", VRF0Name, VRF1Name, "2A00:0C98:2060:A000:0001:0000:1d1e:ca75/64", "2A00:0C98:2060:A000:0001:0000:1d1e:ca75/64"),
	)

	DescribeTable("handles tableid conflicts",
		func(vrf0, vrf1 string, tableid0, tableid1 int, expectedError string) {
			conf0 := configWithTableFor("test", IF0Name, vrf0, "10.0.0.2/24", tableid0)
			conf1 := configWithTableFor("test1", IF1Name, vrf1, "10.0.0.2/24", tableid1)

			By("Adding the first interface to first vrf", func() {
				err := originalNS.Do(func(ns.NetNS) error {
					defer GinkgoRecover()
					args := &skel.CmdArgs{
						ContainerID: "dummy",
						Netns:       targetNS.Path(),
						IfName:      IF0Name,
						StdinData:   conf0,
					}
					_, _, err := testutils.CmdAddWithArgs(args, func() error {
						return cmdAdd(args)
					})
					Expect(err).NotTo(HaveOccurred())
					return nil
				})
				Expect(err).NotTo(HaveOccurred())
			})

			By("Checking that the first vrf has the right routing table", func() {
				err := targetNS.Do(func(ns.NetNS) error {
					defer GinkgoRecover()

					l, err := netlinksafe.LinkByName(vrf0)
					Expect(err).NotTo(HaveOccurred())
					vrf := l.(*netlink.Vrf)
					Expect(vrf.Table).To(Equal(uint32(tableid0)))
					return nil
				})
				Expect(err).NotTo(HaveOccurred())
			})

			By("Adding the second interface to second vrf", func() {
				err := originalNS.Do(func(ns.NetNS) error {
					defer GinkgoRecover()
					args := &skel.CmdArgs{
						ContainerID: "dummy",
						Netns:       targetNS.Path(),
						IfName:      IF1Name,
						StdinData:   conf1,
					}
					_, _, err := testutils.CmdAddWithArgs(args, func() error {
						return cmdAdd(args)
					})
					return err
				})
				if expectedError != "" {
					Expect(err).To(HaveOccurred())
					Expect(err.Error()).To(ContainSubstring(expectedError))
					return
				}
				Expect(err).NotTo(HaveOccurred())
			})
		},
		Entry("same vrf with same tableid", VRF0Name, VRF0Name, 1001, 1001, ""),
		Entry("different vrf with same tableid", VRF0Name, VRF1Name, 1001, 1001, ""),
		Entry("same vrf with different tableids", VRF0Name, VRF0Name, 1001, 1002, "already exist with different routing table"),
	)

	It("removes the VRF only when the last interface is removed", func() {
		conf0 := configFor("test", IF0Name, VRF0Name, "10.0.0.2/24")
		conf1 := configFor("test1", IF1Name, VRF0Name, "10.0.0.2/24")

		By("Adding the two interfaces to the VRF", func() {
			err := originalNS.Do(func(ns.NetNS) error {
				defer GinkgoRecover()
				args := &skel.CmdArgs{
					ContainerID: "dummy",
					Netns:       targetNS.Path(),
					IfName:      IF0Name,
					StdinData:   conf0,
				}
				_, _, err := testutils.CmdAddWithArgs(args, func() error {
					return cmdAdd(args)
				})
				Expect(err).NotTo(HaveOccurred())

				args = &skel.CmdArgs{
					ContainerID: "dummy",
					Netns:       targetNS.Path(),
					IfName:      IF1Name,
					StdinData:   conf1,
				}
				_, _, err = testutils.CmdAddWithArgs(args, func() error {
					return cmdAdd(args)
				})
				Expect(err).NotTo(HaveOccurred())
				return nil
			})
			Expect(err).NotTo(HaveOccurred())
		})

		By("Checking that the two interfaces are added to the VRF", func() {
			targetNS.Do(func(ns.NetNS) error {
				defer GinkgoRecover()
				checkInterfaceOnVRF(VRF0Name, IF0Name)
				checkInterfaceOnVRF(VRF0Name, IF1Name)
				return nil
			})
		})

		By("Removing the first interface from VRF, removing the interface", func() {
			err := originalNS.Do(func(ns.NetNS) error {
				defer GinkgoRecover()
				args := &skel.CmdArgs{
					ContainerID: "dummy",
					Netns:       targetNS.Path(),
					IfName:      IF0Name,
					StdinData:   conf0,
				}
				err := testutils.CmdDelWithArgs(args, func() error {
					return cmdDel(args)
				})
				Expect(err).NotTo(HaveOccurred())
				return nil
			})
			Expect(err).NotTo(HaveOccurred())

			err = targetNS.Do(func(ns.NetNS) error {
				link, err := netlinksafe.LinkByName(IF0Name)
				Expect(err).NotTo(HaveOccurred())
				err = netlink.LinkDel(link)
				Expect(err).NotTo(HaveOccurred())
				return nil
			})
			Expect(err).NotTo(HaveOccurred())
		})

		By("Checking that the second interface is still on the VRF and that VRF still exists", func() {
			targetNS.Do(func(ns.NetNS) error {
				defer GinkgoRecover()
				checkInterfaceOnVRF(VRF0Name, IF1Name)
				return nil
			})
		})

		By("Removing the second interface from VRF, deleting the second interface", func() {
			err := originalNS.Do(func(ns.NetNS) error {
				defer GinkgoRecover()
				args := &skel.CmdArgs{
					ContainerID: "dummy",
					Netns:       targetNS.Path(),
					IfName:      IF1Name,
					StdinData:   conf1,
				}
				err := testutils.CmdDelWithArgs(args, func() error {
					return cmdDel(args)
				})
				Expect(err).NotTo(HaveOccurred())
				return nil
			})
			Expect(err).NotTo(HaveOccurred())

			err = targetNS.Do(func(ns.NetNS) error {
				link, err := netlinksafe.LinkByName(IF1Name)
				Expect(err).NotTo(HaveOccurred())
				err = netlink.LinkDel(link)
				Expect(err).NotTo(HaveOccurred())
				return nil
			})
			Expect(err).NotTo(HaveOccurred())
		})

		By("Checking that the VRF is removed", func() {
			targetNS.Do(func(ns.NetNS) error {
				defer GinkgoRecover()
				_, err := netlinksafe.LinkByName(VRF0Name)
				Expect(err).To(HaveOccurred())
				return nil
			})
		})
	})

	It("configures and deconfigures VRF with CNI 0.4.0 ADD/DEL", func() {
		conf := []byte(fmt.Sprintf(`{
	"name": "test",
	"type": "vrf",
	"cniVersion": "0.4.0",
	"vrfName": "%s",
	"prevResult": {
		"interfaces": [
			{"name": "%s", "sandbox":"netns"}
		],
		"ips": [
			{
				"version": "4",
				"address": "10.0.0.2/24",
				"gateway": "10.0.0.1",
				"interface": 0
			}
		]
	}
}`, VRF0Name, IF0Name))

		args := &skel.CmdArgs{
			ContainerID: "dummy",
			Netns:       targetNS.Path(),
			IfName:      IF0Name,
			StdinData:   conf,
		}
		var prevRes types.Result
		err := originalNS.Do(func(ns.NetNS) error {
			defer GinkgoRecover()

			prevRes, _, err := testutils.CmdAddWithArgs(args, func() error {
				return cmdAdd(args)
			})
			Expect(err).NotTo(HaveOccurred())

			result, err := current.GetResult(prevRes)
			Expect(err).NotTo(HaveOccurred())

			Expect(result.Interfaces).To(HaveLen(1))
			Expect(result.Interfaces[0].Name).To(Equal(IF0Name))
			Expect(result.IPs).To(HaveLen(1))
			Expect(result.IPs[0].Address.String()).To(Equal("10.0.0.2/24"))
			return nil
		})
		Expect(err).NotTo(HaveOccurred())

		err = targetNS.Do(func(ns.NetNS) error {
			defer GinkgoRecover()
			checkInterfaceOnVRF(VRF0Name, IF0Name)
			return nil
		})

		err = originalNS.Do(func(ns.NetNS) error {
			defer GinkgoRecover()
			cniVersion := "0.4.0"
			n := &VRFNetConf{}
			err = json.Unmarshal(conf, &n)
			_, confString, err := buildOneConfig("testConfig", cniVersion, n, prevRes)
			Expect(err).NotTo(HaveOccurred())

			args.StdinData = confString

			err = testutils.CmdCheckWithArgs(args, func() error {
				return cmdCheck(args)
			})
			Expect(err).NotTo(HaveOccurred())

			err = testutils.CmdDel(originalNS.Path(),
				args.ContainerID, "", func() error { return cmdDel(args) })
			Expect(err).NotTo(HaveOccurred())

			return nil
		})
		Expect(err).NotTo(HaveOccurred())
	})
})

var _ = Describe("unit tests", func() {
	DescribeTable("When looking for a table id",
		func(links []netlink.Link, expected uint32, expectFail bool) {
			newID, err := findFreeRoutingTableID(links)
			if expectFail {
				Expect(err).To(HaveOccurred())
				return
			}
			Expect(err).NotTo(HaveOccurred())
			Expect(newID).To(Equal(expected))
		},
		Entry("Finds first free one", []netlink.Link{
			&netlink.Vrf{Table: 1},
			&netlink.Vrf{Table: 2},
			&netlink.Vrf{Table: 3},
			&netlink.Vrf{Table: 5},
		}, uint32(4), false),
		Entry("Ignores non VRFs free one", []netlink.Link{
			&netlink.Vrf{Table: 1},
			&netlink.Vrf{Table: 2},
			&netlink.Dummy{},
			&netlink.Vrf{Table: 5},
		}, uint32(3), false),
		Entry("Takes the first when no vrfs are there", []netlink.Link{},
			uint32(1), false),
		Entry("Works with 999 vrfs already assigned", func() []netlink.Link {
			res := []netlink.Link{}
			for i := uint32(1); i < 1000; i++ {
				res = append(res, &netlink.Vrf{Table: i})
			}
			return res
		}(), uint32(1000), false),
	)

	Describe("routeForInterface", func() {
		ipv6Default := &net.IPNet{
			IP:   net.IPv6zero,
			Mask: net.CIDRMask(0, 128),
		}
		const (
			eth0Index = 2
			net1Index = 5
		)

		It("keeps a single-hop route on the target interface", func() {
			route := netlink.Route{
				LinkIndex: net1Index,
				Dst:       ipv6Default,
				Gw:        net.ParseIP("2001:db8:1::1"),
				Priority:  1024,
				Scope:     netlink.SCOPE_UNIVERSE,
			}

			got, ok := routeForInterface(route, net1Index)
			Expect(ok).To(BeTrue())
			Expect(got).To(Equal(route))
		})

		It("rejects a single-hop route on another interface", func() {
			route := netlink.Route{
				LinkIndex: eth0Index,
				Dst:       ipv6Default,
				Gw:        net.ParseIP("fe80::1"),
				Priority:  1024,
				Scope:     netlink.SCOPE_UNIVERSE,
			}

			_, ok := routeForInterface(route, net1Index)
			Expect(ok).To(BeFalse())
		})

		It("extracts only the target nexthop from an IPv6 ECMP default route", func() {
			// Simulates main-table ::/0 after IPAM added a second default via net1
			// while eth0 already had one, so the kernel merged them into multipath.
			route := netlink.Route{
				LinkIndex: 0,
				Dst:       ipv6Default,
				Priority:  1024,
				Scope:     netlink.SCOPE_UNIVERSE,
				MultiPath: []*netlink.NexthopInfo{
					{LinkIndex: eth0Index, Gw: net.ParseIP("fe80::1"), Hops: 0},
					{LinkIndex: net1Index, Gw: net.ParseIP("2001:db8:1::1"), Hops: 0},
				},
			}

			got, ok := routeForInterface(route, net1Index)
			Expect(ok).To(BeTrue())
			Expect(got.MultiPath).To(BeNil())
			Expect(got.LinkIndex).To(Equal(net1Index))
			Expect(got.Gw.Equal(net.ParseIP("2001:db8:1::1"))).To(BeTrue())
			Expect(got.Dst.String()).To(Equal("::/0"))
			Expect(got.Priority).To(Equal(1024))
		})

		It("rejects multipath routes with no nexthop on the target interface", func() {
			route := netlink.Route{
				Dst:      ipv6Default,
				Priority: 1024,
				MultiPath: []*netlink.NexthopInfo{
					{LinkIndex: eth0Index, Gw: net.ParseIP("fe80::1")},
				},
			}

			_, ok := routeForInterface(route, net1Index)
			Expect(ok).To(BeFalse())
		})

		It("keeps multiple nexthops when more than one is on the target interface", func() {
			route := netlink.Route{
				Dst: ipv6Default,
				MultiPath: []*netlink.NexthopInfo{
					{LinkIndex: net1Index, Gw: net.ParseIP("2001:db8:1::1"), Hops: 0},
					{LinkIndex: eth0Index, Gw: net.ParseIP("fe80::1"), Hops: 0},
					{LinkIndex: net1Index, Gw: net.ParseIP("2001:db8:1::2"), Hops: 0},
				},
			}

			got, ok := routeForInterface(route, net1Index)
			Expect(ok).To(BeTrue())
			Expect(got.MultiPath).To(HaveLen(2))
			Expect(got.LinkIndex).To(Equal(0))
			Expect(got.Gw).To(BeNil())
			Expect(got.MultiPath[0].Gw.Equal(net.ParseIP("2001:db8:1::1"))).To(BeTrue())
			Expect(got.MultiPath[1].Gw.Equal(net.ParseIP("2001:db8:1::2"))).To(BeTrue())
		})

		It("filters a mixed list down to routes for the target interface", func() {
			routes := []netlink.Route{
				{
					LinkIndex: eth0Index,
					Dst:       ipv6Default,
					Gw:        net.ParseIP("fe80::1"),
				},
				{
					LinkIndex: net1Index,
					Dst: &net.IPNet{
						IP:   net.ParseIP("2001:db8:1::"),
						Mask: net.CIDRMask(64, 128),
					},
					Gw: net.ParseIP("2001:db8:1::1"),
				},
				{
					LinkIndex: 0,
					Dst:       ipv6Default,
					Priority:  1024,
					MultiPath: []*netlink.NexthopInfo{
						{LinkIndex: eth0Index, Gw: net.ParseIP("fe80::1")},
						{LinkIndex: net1Index, Gw: net.ParseIP("2001:db8:1::1")},
					},
				},
			}

			got := routesForInterface(routes, net1Index)
			Expect(got).To(HaveLen(2))
			Expect(got[0].LinkIndex).To(Equal(net1Index))
			Expect(got[0].Dst.String()).To(Equal("2001:db8:1::/64"))
			Expect(got[1].LinkIndex).To(Equal(net1Index))
			Expect(got[1].Gw.Equal(net.ParseIP("2001:db8:1::1"))).To(BeTrue())
			Expect(got[1].MultiPath).To(BeNil())
		})
	})
})

func configFor(name, intf, vrf, ip string) []byte {
	conf := fmt.Sprintf(`{
		"name": "%s",
		"type": "vrf",
		"cniVersion": "0.3.1",
		"vrfName": "%s",
		"prevResult": {
			"interfaces": [
				{"name": "%s", "sandbox":"netns"}
			],
			"ips": [
				{
					"version": "4",
					"address": "%s",
					"gateway": "10.0.0.1",
					"interface": 0
				}
			]
		}
	}`, name, vrf, intf, ip)
	return []byte(conf)
}

func configWithTableFor(name, intf, vrf, ip string, tableID int) []byte {
	conf := fmt.Sprintf(`{
		"name": "%s",
		"type": "vrf",
		"cniVersion": "0.3.1",
		"vrfName": "%s",
		"table": %d,
		"prevResult": {
			"interfaces": [
				{"name": "%s", "sandbox":"netns"}
			],
			"ips": [
				{
					"version": "4",
					"address": "%s",
					"gateway": "10.0.0.1",
					"interface": 0
				}
			]
		}
	}`, name, vrf, tableID, intf, ip)
	return []byte(conf)
}

func configWithRouteFor(name, intf, vrf, ip, route string) []byte {
	conf := fmt.Sprintf(`{
		"name": "%s",
		"type": "vrf",
		"cniVersion": "0.3.1",
		"vrfName": "%s",
		"prevResult": {
			"interfaces": [
				{"name": "%s", "sandbox":"netns"}
			],
			"ips": [
				{
					"version": "4",
					"address": "%s",
					"gateway": "10.0.0.1",
					"interface": 0
				}
			],
			"routes": [
				{
					"dst": "%s",
					"gw": "10.0.0.1"
				}
			]
		}
	}`, name, vrf, intf, ip, route)
	return []byte(conf)
}

func checkInterfaceOnVRF(vrfName, intfName string) {
	vrf, err := netlinksafe.LinkByName(vrfName)
	Expect(err).NotTo(HaveOccurred())
	Expect(vrf).To(BeAssignableToTypeOf(&netlink.Vrf{}))

	link, err := netlinksafe.LinkByName(intfName)
	Expect(err).NotTo(HaveOccurred())
	masterIndx := link.Attrs().MasterIndex
	master, err := netlink.LinkByIndex(masterIndx)
	Expect(err).NotTo(HaveOccurred())
	Expect(master.Attrs().Name).To(Equal(vrfName))
}

func checkRoutesOnVRF(vrfName, intfName string, addrStr string, routesToCheck ...string) {
	l, err := netlinksafe.LinkByName(vrfName)
	Expect(err).NotTo(HaveOccurred())
	Expect(l).To(BeAssignableToTypeOf(&netlink.Vrf{}))

	vrf, ok := l.(*netlink.Vrf)
	Expect(ok).To(BeTrue())

	link, err := netlinksafe.LinkByName(intfName)
	Expect(err).NotTo(HaveOccurred())

	err = netlink.LinkSetUp(link)
	Expect(err).NotTo(HaveOccurred())

	ipAddrs, err := netlinksafe.AddrList(link, netlink.FAMILY_V4)
	Expect(err).NotTo(HaveOccurred())
	Expect(ipAddrs).To(HaveLen(1))
	Expect(ipAddrs[0].IP.String()).To(Equal(addrStr))

	routeFilter := &netlink.Route{
		Table: int(vrf.Table),
	}

	routes, err := netlinksafe.RouteListFiltered(netlink.FAMILY_ALL,
		routeFilter,
		netlink.RT_FILTER_TABLE)
	Expect(err).NotTo(HaveOccurred())

	routesRead := []string{}
	for _, route := range routes {
		routesRead = append(routesRead, route.String())
		Expect(uint32(route.Table)).To(Equal(vrf.Table))
	}
	routesStr := strings.Join(routesRead, "\n")
	for _, route := range routesToCheck {
		Expect(routesStr).To(ContainSubstring(route))
	}

	for _, route := range routes {
		Expect(route.LinkIndex).To(Equal(link.Attrs().Index))
	}
}
