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
	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types/current"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/containernetworking/plugins/pkg/testutils"

	//"fmt"
	"github.com/google/nftables"
	"github.com/vishvananda/netlink"
	"path"
	"strings"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func getTestContainerID(s string) string {
	_, containerID := path.Split(s)
	return strings.ReplaceAll(containerID, "cnitest", "dummy")
}

func validateNftRulesExist(bytes []byte) {
	prevResult := getPrevResult(bytes)

	for _, ip := range prevResult.IPs {
		Expect(ip).To(Equal(true))
	}
}

func validateNftRulesCleanup(bytes []byte) {
	prevResult := getPrevResult(bytes)

	for _, ip := range prevResult.IPs {
		Expect(ip).To(Equal(true))
	}
}

var _ = Describe("firewall plugin nftables backend v0.4.x", func() {
	var originalNS, targetNS ns.NetNS
	const IFNAME string = "dummy0"

	BeforeEach(func() {
		// Create a new NetNS so we don't modify the host
		var err error
		originalNS, err = testutils.NewNS()
		Expect(err).NotTo(HaveOccurred())

		// fmt.Print("\n")
		// fmt.Printf("Host Namespace: %s\n", originalNS.Path())

		err = originalNS.Do(func(ns.NetNS) error {
			defer GinkgoRecover()

			err = netlink.LinkAdd(&netlink.Dummy{
				LinkAttrs: netlink.LinkAttrs{
					Name: IFNAME,
				},
			})
			Expect(err).NotTo(HaveOccurred())
			_, err = netlink.LinkByName(IFNAME)
			Expect(err).NotTo(HaveOccurred())

			// Add netfilter connection
			nftc := &nftables.Conn{}
			defaultDropPolicy := nftables.ChainPolicyDrop
			// Add IPv4 filter table
			filter4Table := nftc.AddTable(&nftables.Table{
				Family: nftables.TableFamilyIPv4,
				Name:   "filter",
			})
			Expect(filter4Table).NotTo(BeNil())
			// Add FORWARD chain in IPv4 filter table
			forwardFilter4TableChain := nftc.AddChain(&nftables.Chain{
				Name:     "FORWARD",
				Table:    filter4Table,
				Type:     nftables.ChainTypeFilter,
				Hooknum:  nftables.ChainHookForward,
				Priority: nftables.ChainPriorityFilter,
				Policy:   &defaultDropPolicy,
			})
			Expect(forwardFilter4TableChain).NotTo(BeNil())
			// Add IPv6 filter table
			filter6Table := nftc.AddTable(&nftables.Table{
				Family: nftables.TableFamilyIPv6,
				Name:   "filter",
			})
			Expect(filter6Table).NotTo(BeNil())
			// Add FORWARD chain in IPv6 filter table
			forwardFilter6TableChain := nftc.AddChain(&nftables.Chain{
				Name:     "FORWARD",
				Table:    filter6Table,
				Type:     nftables.ChainTypeFilter,
				Hooknum:  nftables.ChainHookForward,
				Priority: nftables.ChainPriorityFilter,
				Policy:   &defaultDropPolicy,
			})
			Expect(forwardFilter6TableChain).NotTo(BeNil())
			// Execute netfilter changes
			err = nftc.Flush()
			Expect(err).NotTo(HaveOccurred())
			return nil
		})
		Expect(err).NotTo(HaveOccurred())

		targetNS, err = testutils.NewNS()
		Expect(err).NotTo(HaveOccurred())
		//_, nsName := path.Split(originalNS.Path())
		// fmt.Printf("Container Namespace: %s\n", targetNS.Path())
		// fmt.Printf("Debug: sudo ip netns exec %s nft --debug=netlink list ruleset\n", nsName)
	})

	AfterEach(func() {
		Expect(originalNS.Close()).To(Succeed())
		Expect(targetNS.Close()).To(Succeed())
	})

	It("fails when IP configuration version is invalid using v4.0.x", func() {
		args := &skel.CmdArgs{
			ContainerID: getTestContainerID(targetNS.Path()),
			Netns:       targetNS.Path(),
			IfName:      IFNAME,
			StdinData: []byte(`{
		        "name": "test",
				"type": "firewall",
				"backend": "nftables",
		        "ifName": "dummy0",
				"cniVersion": "0.4.0",
			    "prevResult": {
				    "interfaces": [
					    {"name": "dummy0"}
				    ],
			        "ips": [
			            {
							"version": "4",
						    "address": "192.168.200.10/24",
						    "interface": 0
				        },
			            {
			                "version": "16",
							"address": "2001:db8:1:2::1/64",
						    "interface": 0
					    }
				    ]
		        }
			}`),
		}

		err := originalNS.Do(func(ns.NetNS) error {
			defer GinkgoRecover()

			_, _, err := testutils.CmdAddWithArgs(args, func() error {
				return cmdAdd(args)
			})
			Expect(err).To(HaveOccurred())

			return nil
		})
		Expect(err).NotTo(HaveOccurred())

	})

	It("fails when IP configuration is not present using v4.0.x", func() {
		args := &skel.CmdArgs{
			ContainerID: getTestContainerID(targetNS.Path()),
			Netns:       targetNS.Path(),
			IfName:      IFNAME,
			StdinData: []byte(`{
                "name": "test",
                "type": "firewall",
                "backend": "nftables",
                "ifName": "dummy0",
                "cniVersion": "0.4.0",
                "prevResult": {
                    "interfaces": [
                        {"name": "dummy0"}
                    ]
                }
            }`),
		}

		err := originalNS.Do(func(ns.NetNS) error {
			defer GinkgoRecover()

			_, _, err := testutils.CmdAddWithArgs(args, func() error {
				return cmdAdd(args)
			})
			Expect(err).To(HaveOccurred())

			return nil
		})
		Expect(err).NotTo(HaveOccurred())

	})

	It("configures nftables for a single dual-stack interface using v4.0.x", func() {
		args := &skel.CmdArgs{
			ContainerID: getTestContainerID(targetNS.Path()),
			Netns:       targetNS.Path(),
			IfName:      IFNAME,
			StdinData: []byte(`{
                "name": "test",
                "type": "firewall",
                "backend": "nftables",
                "ifName": "dummy0",
                "cniVersion": "0.4.0",
                "prevResult": {
                    "interfaces": [
                        {"name": "dummy0"}
                    ],
                    "ips": [
                        {
                            "version": "4",
                            "address": "192.168.200.10/24",
                            "interface": 0
                        },
                        {
                            "version": "6",
                            "address": "2001:db8:1:2::1/64",
                            "interface": 0
                        }
                    ]
                }
            }`),
		}

		err := originalNS.Do(func(ns.NetNS) error {
			defer GinkgoRecover()

			r, _, err := testutils.CmdAddWithArgs(args, func() error {
				return cmdAdd(args)
			})
			Expect(err).NotTo(HaveOccurred())

			_, err = current.GetResult(r)
			Expect(err).NotTo(HaveOccurred())

			err = testutils.CmdCheckWithArgs(args, func() error {
				return cmdCheck(args)
			})
			Expect(err).NotTo(HaveOccurred())
			//validateNftRulesExist(args.StdinData)

			err = testutils.CmdDelWithArgs(args, func() error {
				return cmdDel(args)
			})
			Expect(err).NotTo(HaveOccurred())
			//validateNftRulesCleanup(args.StdinData)
			return nil
		})
		Expect(err).NotTo(HaveOccurred())
	})

	It("configures nftables for two dual-stack interfaces using v4.0.x", func() {
		args := &skel.CmdArgs{
			ContainerID: getTestContainerID(targetNS.Path()),
			Netns:       targetNS.Path(),
			IfName:      IFNAME,
			StdinData: []byte(`{
            "name": "test",
            "type": "firewall",
            "backend": "nftables",
            "ifName": "dummy0",
            "cniVersion": "0.4.0",
            "prevResult": {
                "interfaces": [
                    {"name": "dummy0"},
                    {"name": "dummy1"}
                ],
                "ips": [
                    {
                        "version": "4",
                        "address": "192.168.100.100/24",
                        "interface": 0
                    },
                    {
                        "version": "6",
                        "address": "2001:db8:100:100::1/64",
                        "interface": 0
                    },
                    {
                        "version": "4",
                        "address": "192.168.200.200/24",
                        "interface": 1
                    },
                    {
                        "version": "6",
                        "address": "2001:db8:200:200::1/64",
                        "interface": 1
                    }
                ]
            }
        }`),
		}

		err := originalNS.Do(func(ns.NetNS) error {
			defer GinkgoRecover()

			r, _, err := testutils.CmdAddWithArgs(args, func() error {
				return cmdAdd(args)
			})
			Expect(err).NotTo(HaveOccurred())

			_, err = current.GetResult(r)
			Expect(err).NotTo(HaveOccurred())

			err = testutils.CmdCheckWithArgs(args, func() error {
				return cmdCheck(args)
			})
			Expect(err).NotTo(HaveOccurred())
			//validateNftRulesExist(args.StdinData)

			err = testutils.CmdDelWithArgs(args, func() error {
				return cmdDel(args)
			})
			Expect(err).NotTo(HaveOccurred())
			//validateNftRulesCleanup(args.StdinData)
			return nil
		})
		Expect(err).NotTo(HaveOccurred())
	})

	It("configures nftables for a single IPv4-only interface using v4.0.x", func() {
		args := &skel.CmdArgs{
			ContainerID: getTestContainerID(targetNS.Path()),
			Netns:       targetNS.Path(),
			IfName:      IFNAME,
			StdinData: []byte(`{
            "name": "test",
            "type": "firewall",
            "backend": "nftables",
            "ifName": "dummy0",
            "cniVersion": "0.4.0",
            "prevResult": {
                "interfaces": [
                    {"name": "dummy0"}
                ],
                "ips": [
                    {
                        "version": "4",
                        "address": "192.168.100.100/24",
                        "interface": 0
                    }
                ]
            }}`),
		}

		err := originalNS.Do(func(ns.NetNS) error {
			defer GinkgoRecover()

			r, _, err := testutils.CmdAddWithArgs(args, func() error {
				return cmdAdd(args)
			})
			Expect(err).NotTo(HaveOccurred())

			_, err = current.GetResult(r)
			Expect(err).NotTo(HaveOccurred())

			err = testutils.CmdCheckWithArgs(args, func() error {
				return cmdCheck(args)
			})
			Expect(err).NotTo(HaveOccurred())
			//validateNftRulesExist(args.StdinData)

			err = testutils.CmdDelWithArgs(args, func() error {
				return cmdDel(args)
			})
			Expect(err).NotTo(HaveOccurred())
			//validateNftRulesCleanup(args.StdinData)
			return nil
		})
		Expect(err).NotTo(HaveOccurred())
	})

	It("configures nftables for a single IPv6-only interface using v4.0.x", func() {
		args := &skel.CmdArgs{
			ContainerID: getTestContainerID(targetNS.Path()),
			Netns:       targetNS.Path(),
			IfName:      IFNAME,
			StdinData: []byte(`{
            "name": "test",
            "type": "firewall",
            "backend": "nftables",
            "ifName": "dummy0",
            "cniVersion": "0.4.0",
            "prevResult": {
                "interfaces": [
                    {"name": "dummy0"}
                ],
                "ips": [
                {
                    "version": "6",
                    "address": "2001:db8:100:100::1/64",
                    "interface": 0
                }
                ]
            }
        }`),
		}

		err := originalNS.Do(func(ns.NetNS) error {
			defer GinkgoRecover()

			// return nil

			r, _, err := testutils.CmdAddWithArgs(args, func() error {
				return cmdAdd(args)
			})
			Expect(err).NotTo(HaveOccurred())

			_, err = current.GetResult(r)
			Expect(err).NotTo(HaveOccurred())

			err = testutils.CmdCheckWithArgs(args, func() error {
				return cmdCheck(args)
			})
			Expect(err).NotTo(HaveOccurred())
			//validateNftRulesExist(args.StdinData)

			err = testutils.CmdDelWithArgs(args, func() error {
				return cmdDel(args)
			})
			Expect(err).NotTo(HaveOccurred())
			//validateNftRulesCleanup(args.StdinData)
			return nil
		})
		Expect(err).NotTo(HaveOccurred())
	})

})
