// Copyright 2023 CNI authors
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
	"math"
	"net"
	"syscall"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/vishvananda/netlink"

	"github.com/containernetworking/cni/pkg/skel"
	types100 "github.com/containernetworking/cni/pkg/types/100"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/containernetworking/plugins/pkg/testutils"
)

var _ = Describe("bandwidth config test", func() {
	var (
		hostNs          ns.NetNS
		containerNs     ns.NetNS
		ifbDeviceName   string
		hostIfname      string
		containerIfname string
		hostIP          net.IP
		containerIP     net.IP
		hostIfaceMTU    int
	)

	BeforeEach(func() {
		var err error

		hostIfname = "host-veth"
		containerIfname = "container-veth"

		hostNs, err = testutils.NewNS()
		Expect(err).NotTo(HaveOccurred())

		containerNs, err = testutils.NewNS()
		Expect(err).NotTo(HaveOccurred())

		hostIP = net.IP{169, 254, 0, 1}
		containerIP = net.IP{10, 254, 0, 1}
		hostIfaceMTU = 1024
		ifbDeviceName = "bwpa8eda89404b7"

		createVeth(hostNs, hostIfname, containerNs, containerIfname, hostIP, containerIP, hostIfaceMTU)
	})

	AfterEach(func() {
		Expect(containerNs.Close()).To(Succeed())
		Expect(testutils.UnmountNS(containerNs)).To(Succeed())
		Expect(hostNs.Close()).To(Succeed())
		Expect(testutils.UnmountNS(hostNs)).To(Succeed())
	})

	// Bandwidth requires host-side interface info, and thus only
	// supports 0.3.0 and later CNI versions
	for _, ver := range []string{"0.3.0", "0.3.1", "0.4.0", "1.0.0"} {
		// Redefine ver inside for scope so real value is picked up by each dynamically defined It()
		// See Gingkgo's "Patterns for dynamically generating tests" documentation.
		ver := ver

		Describe("cmdADD", func() {
			It(fmt.Sprintf("[%s] fails with invalid UnshapedSubnets", ver), func() {
				conf := fmt.Sprintf(`{
			"cniVersion": "%s",
			"name": "cni-plugin-bandwidth-test",
			"type": "bandwidth",
			"ingressRate": 123,
			"ingressBurst": 123,
			"egressRate": 123,
			"egressBurst": 123,
			"unshapedSubnets": ["10.0.0.0/8", "hello"],
			"prevResult": {
				"interfaces": [
					{
						"name": "%s",
						"sandbox": ""
					},
					{
						"name": "%s",
						"sandbox": "%s"
					}
				],
				"ips": [
					{
						"version": "4",
						"address": "%s/24",
						"gateway": "10.0.0.1",
						"interface": 1
					}
				],
				"routes": []
			}
		}`, ver, hostIfname, containerIfname, containerNs.Path(), containerIP.String())

				args := &skel.CmdArgs{
					ContainerID: "dummy",
					Netns:       containerNs.Path(),
					IfName:      "eth0",
					StdinData:   []byte(conf),
				}

				Expect(hostNs.Do(func(netNS ns.NetNS) error {
					defer GinkgoRecover()

					_, _, err := testutils.CmdAdd(containerNs.Path(), args.ContainerID, "", []byte(conf), func() error { return cmdAdd(args) })
					Expect(err).To(MatchError("bad subnet \"hello\" provided, details invalid CIDR address: hello"))
					return nil
				})).To(Succeed())
			})

			It(fmt.Sprintf("[%s] fails with invalid ShapedSubnets", ver), func() {
				conf := fmt.Sprintf(`{
			"cniVersion": "%s",
			"name": "cni-plugin-bandwidth-test",
			"type": "bandwidth",
			"ingressRate": 123,
			"ingressBurst": 123,
			"egressRate": 123,
			"egressBurst": 123,
			"ShapedSubnets": ["10.0.0.0/8", "hello"],
			"prevResult": {
				"interfaces": [
					{
						"name": "%s",
						"sandbox": ""
					},
					{
						"name": "%s",
						"sandbox": "%s"
					}
				],
				"ips": [
					{
						"version": "4",
						"address": "%s/24",
						"gateway": "10.0.0.1",
						"interface": 1
					}
				],
				"routes": []
			}
		}`, ver, hostIfname, containerIfname, containerNs.Path(), containerIP.String())

				args := &skel.CmdArgs{
					ContainerID: "dummy",
					Netns:       containerNs.Path(),
					IfName:      "eth0",
					StdinData:   []byte(conf),
				}

				Expect(hostNs.Do(func(netNS ns.NetNS) error {
					defer GinkgoRecover()

					_, _, err := testutils.CmdAdd(containerNs.Path(), args.ContainerID, "", []byte(conf), func() error { return cmdAdd(args) })
					Expect(err).To(MatchError("bad subnet \"hello\" provided, details invalid CIDR address: hello"))
					return nil
				})).To(Succeed())
			})

			It(fmt.Sprintf("[%s] fails with both ShapedSubnets and UnShapedSubnets specified", ver), func() {
				conf := fmt.Sprintf(`{
			"cniVersion": "%s",
			"name": "cni-plugin-bandwidth-test",
			"type": "bandwidth",
			"ingressRate": 123,
			"ingressBurst": 123,
			"egressRate": 123,
			"egressBurst": 123,
			"ShapedSubnets": ["10.0.0.0/8"],
			"UnShapedSubnets": ["192.168.0.0/16"],
			"prevResult": {
				"interfaces": [
					{
						"name": "%s",
						"sandbox": ""
					},
					{
						"name": "%s",
						"sandbox": "%s"
					}
				],
				"ips": [
					{
						"version": "4",
						"address": "%s/24",
						"gateway": "10.0.0.1",
						"interface": 1
					}
				],
				"routes": []
			}
		}`, ver, hostIfname, containerIfname, containerNs.Path(), containerIP.String())

				args := &skel.CmdArgs{
					ContainerID: "dummy",
					Netns:       containerNs.Path(),
					IfName:      "eth0",
					StdinData:   []byte(conf),
				}

				Expect(hostNs.Do(func(netNS ns.NetNS) error {
					defer GinkgoRecover()

					_, _, err := testutils.CmdAdd(containerNs.Path(), args.ContainerID, "", []byte(conf), func() error { return cmdAdd(args) })
					Expect(err).To(MatchError("unshapedSubnets and shapedSubnets cannot be both specified, one of them should be discarded"))
					return nil
				})).To(Succeed())
			})

			It(fmt.Sprintf("[%s] fails an invalid ingress config", ver), func() {
				conf := fmt.Sprintf(`{
			"cniVersion": "%s",
			"name": "cni-plugin-bandwidth-test",
			"type": "bandwidth",
			"ingressRate": 0,
			"ingressBurst": 123,
			"egressRate": 123,
			"egressBurst": 123,
			"prevResult": {
				"interfaces": [
					{
						"name": "%s",
						"sandbox": ""
					},
					{
						"name": "%s",
						"sandbox": "%s"
					}
				],
				"ips": [
					{
						"version": "4",
						"address": "%s/24",
						"gateway": "10.0.0.1",
						"interface": 1
					}
				],
				"routes": []
			}
		}`, ver, hostIfname, containerIfname, containerNs.Path(), containerIP.String())

				args := &skel.CmdArgs{
					ContainerID: "dummy",
					Netns:       containerNs.Path(),
					IfName:      "eth0",
					StdinData:   []byte(conf),
				}

				Expect(hostNs.Do(func(netNS ns.NetNS) error {
					defer GinkgoRecover()

					_, _, err := testutils.CmdAdd(containerNs.Path(), args.ContainerID, "", []byte(conf), func() error { return cmdAdd(args) })
					Expect(err).To(MatchError("if burst is set, rate must also be set"))
					return nil
				})).To(Succeed())
			})

			It(fmt.Sprintf("[%s] fails an invalid egress config", ver), func() {
				conf := fmt.Sprintf(`{
			"cniVersion": "%s",
			"name": "cni-plugin-bandwidth-test",
			"type": "bandwidth",
			"ingressRate": 123,
			"ingressBurst": 123,
			"egressRate": 0,
			"egressBurst": 123,
			"prevResult": {
				"interfaces": [
					{
						"name": "%s",
						"sandbox": ""
					},
					{
						"name": "%s",
						"sandbox": "%s"
					}
				],
				"ips": [
					{
						"version": "4",
						"address": "%s/24",
						"gateway": "10.0.0.1",
						"interface": 1
					}
				],
				"routes": []
			}
		}`, ver, hostIfname, containerIfname, containerNs.Path(), containerIP.String())

				args := &skel.CmdArgs{
					ContainerID: "dummy",
					Netns:       containerNs.Path(),
					IfName:      "eth0",
					StdinData:   []byte(conf),
				}

				Expect(hostNs.Do(func(netNS ns.NetNS) error {
					defer GinkgoRecover()

					_, _, err := testutils.CmdAdd(containerNs.Path(), args.ContainerID, "", []byte(conf), func() error { return cmdAdd(args) })
					Expect(err).To(MatchError("if burst is set, rate must also be set"))
					return nil
				})).To(Succeed())
			})

			// Runtime config parameters are expected to be preempted by the global config ones whenever specified
			It(fmt.Sprintf("[%s] should apply static config when both static config and runtime config exist", ver), func() {
				conf := fmt.Sprintf(`{
			"cniVersion": "%s",
			"name": "cni-plugin-bandwidth-test",
			"type": "bandwidth",
			"ingressRate": 0,
			"ingressBurst": 0,
			"egressRate": 123,
			"egressBurst": 123,
			"unshapedSubnets": ["192.168.0.0/24"],
			"runtimeConfig": {
				"bandWidth": {
					"ingressRate": 8,
					"ingressBurst": 8,
					"egressRate": 16,
					"egressBurst": 9,
					"unshapedSubnets": ["10.0.0.0/8", "fd00:db8:abcd:1234:e000::/68"]
				}
			},
			"prevResult": {
				"interfaces": [
					{
						"name": "%s",
						"sandbox": ""
					},
					{
						"name": "%s",
						"sandbox": "%s"
					}
				],
				"ips": [
					{
						"version": "4",
						"address": "%s/24",
						"gateway": "10.0.0.1",
						"interface": 1
					}
				],
				"routes": []
			}
		}`, ver, hostIfname, containerIfname, containerNs.Path(), containerIP.String())

				args := &skel.CmdArgs{
					ContainerID: "dummy",
					Netns:       containerNs.Path(),
					IfName:      containerIfname,
					StdinData:   []byte(conf),
				}

				Expect(hostNs.Do(func(netNS ns.NetNS) error {
					defer GinkgoRecover()
					r, out, err := testutils.CmdAdd(containerNs.Path(), args.ContainerID, "", []byte(conf), func() error { return cmdAdd(args) })
					Expect(err).NotTo(HaveOccurred(), string(out))
					result, err := types100.GetResult(r)
					Expect(err).NotTo(HaveOccurred())

					Expect(result.Interfaces).To(HaveLen(3))
					Expect(result.Interfaces[2].Name).To(Equal(ifbDeviceName))
					Expect(result.Interfaces[2].Sandbox).To(Equal(""))

					ifbLink, err := netlink.LinkByName(ifbDeviceName)
					Expect(err).NotTo(HaveOccurred())
					Expect(ifbLink.Attrs().MTU).To(Equal(hostIfaceMTU))

					qdiscs, err := netlink.QdiscList(ifbLink)
					Expect(err).NotTo(HaveOccurred())

					Expect(qdiscs).To(HaveLen(1))
					Expect(qdiscs[0].Attrs().LinkIndex).To(Equal(ifbLink.Attrs().Index))
					Expect(qdiscs[0]).To(BeAssignableToTypeOf(&netlink.Htb{}))
					Expect(qdiscs[0].(*netlink.Htb).Defcls).To(Equal(uint32(ShapedClassMinorID)))

					classes, err := netlink.ClassList(ifbLink, qdiscs[0].Attrs().Handle)

					Expect(err).NotTo(HaveOccurred())
					Expect(classes).To(HaveLen(2))

					// Uncapped class
					Expect(classes[0]).To(BeAssignableToTypeOf(&netlink.HtbClass{}))
					Expect(classes[0].(*netlink.HtbClass).Handle).To(Equal(netlink.MakeHandle(1, 1)))
					Expect(classes[0].(*netlink.HtbClass).Rate).To(Equal(UncappedRate))
					Expect(classes[0].(*netlink.HtbClass).Buffer).To(Equal(uint32(0)))
					Expect(classes[0].(*netlink.HtbClass).Ceil).To(Equal(UncappedRate))
					Expect(classes[0].(*netlink.HtbClass).Cbuffer).To(Equal(uint32(0)))

					// Class with traffic shapping settings
					Expect(classes[1]).To(BeAssignableToTypeOf(&netlink.HtbClass{}))
					Expect(classes[1].(*netlink.HtbClass).Handle).To(Equal(netlink.MakeHandle(1, uint16(qdiscs[0].(*netlink.Htb).Defcls))))
					Expect(classes[1].(*netlink.HtbClass).Rate).To(Equal(uint64(15)))
					// Expect(classes[1].(*netlink.HtbClass).Buffer).To(Equal(uint32(7812500)))
					Expect(classes[1].(*netlink.HtbClass).Ceil).To(Equal(uint64(30)))
					// Expect(classes[1].(*netlink.HtbClass).Cbuffer).To(Equal(uint32(0)))

					filters, err := netlink.FilterList(ifbLink, qdiscs[0].Attrs().Handle)
					Expect(err).NotTo(HaveOccurred())
					Expect(filters).To(HaveLen(1))

					// traffic to 192.168.0.0/24 redirected to uncapped class
					Expect(filters[0]).To(BeAssignableToTypeOf(&netlink.U32{}))
					Expect(filters[0].(*netlink.U32).Actions).To(BeEmpty())
					Expect(filters[0].Attrs().Protocol).To(Equal(uint16(syscall.ETH_P_IP)))
					Expect(filters[0].Attrs().LinkIndex).To(Equal(ifbLink.Attrs().Index))
					Expect(filters[0].Attrs().Priority).To(Equal(uint16(16)))
					Expect(filters[0].Attrs().Parent).To(Equal(qdiscs[0].Attrs().Handle))
					Expect(filters[0].(*netlink.U32).ClassId).To(Equal(netlink.MakeHandle(1, 1)))

					filterSel := filters[0].(*netlink.U32).Sel
					Expect(filterSel).To(BeAssignableToTypeOf(&netlink.TcU32Sel{}))
					Expect(filterSel.Flags).To(Equal(uint8(netlink.TC_U32_TERMINAL)))
					Expect(filterSel.Keys).To(HaveLen(1))
					Expect(filterSel.Nkeys).To(Equal(uint8(1)))

					// The filter should match to 192.168.0.0/24 dst address in other words it should be:
					// match c0a80000/ffffff00 at 16
					selKey := filterSel.Keys[0]
					Expect(selKey.Val).To(Equal(uint32(192*math.Pow(256, 3) + 168*math.Pow(256, 2))))
					Expect(selKey.Off).To(Equal(int32(16)))
					Expect(selKey.Mask).To(Equal(uint32(255*math.Pow(256, 3) + 255*math.Pow(256, 2) + 255*256)))

					hostVethLink, err := netlink.LinkByName(hostIfname)
					Expect(err).NotTo(HaveOccurred())

					qdiscFilters, err := netlink.FilterList(hostVethLink, netlink.MakeHandle(0xffff, 0))
					Expect(err).NotTo(HaveOccurred())

					Expect(qdiscFilters).To(HaveLen(1))
					Expect(qdiscFilters[0].(*netlink.U32).Actions[0].(*netlink.MirredAction).Ifindex).To(Equal(ifbLink.Attrs().Index))

					return nil
				})).To(Succeed())

				// Container ingress (host egress)
				Expect(hostNs.Do(func(n ns.NetNS) error {
					defer GinkgoRecover()

					vethLink, err := netlink.LinkByName(hostIfname)
					Expect(err).NotTo(HaveOccurred())

					qdiscs, err := netlink.QdiscList(vethLink)
					Expect(err).NotTo(HaveOccurred())

					// No ingress QoS just mirroring
					Expect(qdiscs).To(HaveLen(2))
					Expect(qdiscs[0].Attrs().LinkIndex).To(Equal(vethLink.Attrs().Index))
					Expect(qdiscs[0]).NotTo(BeAssignableToTypeOf(&netlink.Htb{}))
					Expect(qdiscs[1]).NotTo(BeAssignableToTypeOf(&netlink.Htb{}))

					return nil
				})).To(Succeed())
			})

			It(fmt.Sprintf("[%s] should apply static config when both static config and runtime config exist (bad config example)", ver), func() {
				conf := fmt.Sprintf(`{
			"cniVersion": "%s",
			"name": "cni-plugin-bandwidth-test",
			"type": "bandwidth",
			"ingressRate": 0,
			"ingressBurst": 123,
			"egressRate": 123,
			"egressBurst": 123,
			"runtimeConfig": {
				"bandWidth": {
					"ingressRate": 8,
					"ingressBurst": 8,
					"egressRate": 16,
					"egressBurst": 9
				}
			},
			"prevResult": {
				"interfaces": [
					{
						"name": "%s",
						"sandbox": ""
					},
					{
						"name": "%s",
						"sandbox": "%s"
					}
				],
				"ips": [
					{
						"version": "4",
						"address": "%s/24",
						"gateway": "10.0.0.1",
						"interface": 1
					}
				],
				"routes": []
			}
		}`, ver, hostIfname, containerIfname, containerNs.Path(), containerIP.String())

				args := &skel.CmdArgs{
					ContainerID: "dummy",
					Netns:       containerNs.Path(),
					IfName:      "eth0",
					StdinData:   []byte(conf),
				}

				Expect(hostNs.Do(func(netNS ns.NetNS) error {
					defer GinkgoRecover()

					_, _, err := testutils.CmdAdd(containerNs.Path(), args.ContainerID, "", []byte(conf), func() error { return cmdAdd(args) })
					Expect(err).To(MatchError("if burst is set, rate must also be set"))
					return nil
				})).To(Succeed())
			})
		})
	}

	Describe("Validating input", func() {
		It("Should allow only 4GB burst rate", func() {
			err := validateRateAndBurst(5000, 4*1024*1024*1024*8-16) // 2 bytes less than the max should pass
			Expect(err).NotTo(HaveOccurred())
			err = validateRateAndBurst(5000, 4*1024*1024*1024*8) // we're 1 bit above MaxUint32
			Expect(err).To(HaveOccurred())
			err = validateRateAndBurst(0, 1)
			Expect(err).To(HaveOccurred())
			err = validateRateAndBurst(1, 0)
			Expect(err).To(HaveOccurred())
			err = validateRateAndBurst(0, 0)
			Expect(err).NotTo(HaveOccurred())
		})

		It("Should fail if both ShapedSubnets and UnshapedSubnets are specified", func() {
			err := validateSubnets([]string{"10.0.0.0/8"}, []string{"192.168.0.0/24"})
			Expect(err).To(HaveOccurred())
		})

		It("Should fail if specified UnshapedSubnets are not valid CIDRs", func() {
			err := validateSubnets([]string{"10.0.0.0/8", "hello"}, []string{})
			Expect(err).To(HaveOccurred())
		})

		It("Should fail if specified ShapedSubnets are not valid CIDRs", func() {
			err := validateSubnets([]string{}, []string{"10.0.0.0/8", "hello"})
			Expect(err).To(HaveOccurred())
		})
	})
})
