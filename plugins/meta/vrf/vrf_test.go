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
	"fmt"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types/current"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/containernetworking/plugins/pkg/testutils"

	"github.com/vishvananda/netlink"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
)

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
