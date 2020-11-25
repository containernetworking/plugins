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

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/cni/pkg/types/current"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/containernetworking/plugins/pkg/testutils"

	"github.com/vishvananda/netlink"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
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

	confBytes, err := json.Marshal(orig)
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

			err = netlink.LinkAdd(&netlink.Dummy{
				LinkAttrs: netlink.LinkAttrs{
					Name: IF0Name,
				},
			})
			Expect(err).NotTo(HaveOccurred())
			_, err = netlink.LinkByName(IF0Name)
			Expect(err).NotTo(HaveOccurred())

			err = netlink.LinkAdd(&netlink.Dummy{
				LinkAttrs: netlink.LinkAttrs{
					Name: IF1Name,
				},
			})
			Expect(err).NotTo(HaveOccurred())
			_, err = netlink.LinkByName(IF0Name)
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

			Expect(len(result.Interfaces)).To(Equal(1))
			Expect(result.Interfaces[0].Name).To(Equal(IF0Name))
			Expect(len(result.IPs)).To(Equal(1))
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

		err = targetNS.Do(func(ns.NetNS) error {
			defer GinkgoRecover()
			checkInterfaceOnVRF(VRF0Name, IF0Name)
			return nil
		})
		Expect(err).NotTo(HaveOccurred())
	})

	It("fails if the interface already has a master set", func() {
		conf := configFor("test", IF0Name, VRF0Name, "10.0.0.2/24")

		By("Setting the interface's master", func() {
			err := targetNS.Do(func(ns.NetNS) error {
				defer GinkgoRecover()
				l, err := netlink.LinkByName(IF0Name)
				Expect(err).NotTo(HaveOccurred())
				br := &netlink.Bridge{
					LinkAttrs: netlink.LinkAttrs{
						Name: "testrbridge",
					},
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
					l, err := netlink.LinkByName(IF0Name)
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
					l, err := netlink.LinkByName(IF1Name)
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

					link, err := netlink.LinkByName(IF0Name)
					Expect(err).NotTo(HaveOccurred())
					addresses, err := netlink.AddrList(link, netlink.FAMILY_ALL)
					Expect(len(addresses)).To(Equal(1))
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

					link, err := netlink.LinkByName(IF1Name)
					Expect(err).NotTo(HaveOccurred())

					addresses, err := netlink.AddrList(link, netlink.FAMILY_ALL)
					Expect(len(addresses)).To(Equal(1))
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
					l0, err := netlink.LinkByName(vrf0)
					Expect(err).NotTo(HaveOccurred())
					Expect(l0).To(BeAssignableToTypeOf(&netlink.Vrf{}))
					l1, err := netlink.LinkByName(vrf1)
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

					l, err := netlink.LinkByName(vrf0)
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
				link, err := netlink.LinkByName(IF0Name)
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
				link, err := netlink.LinkByName(IF1Name)
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
				_, err := netlink.LinkByName(VRF0Name)
				Expect(err).NotTo(BeNil())
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

			Expect(len(result.Interfaces)).To(Equal(1))
			Expect(result.Interfaces[0].Name).To(Equal(IF0Name))
			Expect(len(result.IPs)).To(Equal(1))
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
			err = json.Unmarshal([]byte(conf), &n)
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

func checkInterfaceOnVRF(vrfName, intfName string) {
	vrf, err := netlink.LinkByName(vrfName)
	Expect(err).NotTo(HaveOccurred())
	Expect(vrf).To(BeAssignableToTypeOf(&netlink.Vrf{}))

	link, err := netlink.LinkByName(intfName)
	Expect(err).NotTo(HaveOccurred())
	masterIndx := link.Attrs().MasterIndex
	master, err := netlink.LinkByIndex(masterIndx)
	Expect(err).NotTo(HaveOccurred())
	Expect(master.Attrs().Name).To(Equal(vrfName))
}

func checkLinkHasNoMaster(intfName string) {
	link, err := netlink.LinkByName(intfName)
	Expect(err).NotTo(HaveOccurred())
	masterIndx := link.Attrs().MasterIndex
	Expect(masterIndx).To(Equal(0))
}
