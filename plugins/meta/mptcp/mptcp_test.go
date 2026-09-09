// Copyright 2025 CNI authors
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

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/vishvananda/netlink"

	"github.com/containernetworking/cni/pkg/skel"
	current "github.com/containernetworking/cni/pkg/types/100"
	"github.com/containernetworking/plugins/pkg/netlinksafe"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/containernetworking/plugins/pkg/testutils"
)

func configForEndpoints(name, ifName, ip string, signal, subflow, backup, fullmesh bool) []byte {
	return []byte(fmt.Sprintf(`{
		"name": "%s",
		"type": "mptcp",
		"cniVersion": "1.0.0",
		"endpoints": {
			"signal": %t,
			"subflow": %t,
			"backup": %t,
			"fullmesh": %t
		},
		"prevResult": {
			"interfaces": [
				{"name": "%s", "sandbox": "netns"}
			],
			"ips": [
				{
					"address": "%s",
					"interface": 0
				}
			]
		}
	}`, name, signal, subflow, backup, fullmesh, ifName, ip))
}

func configForEndpointsDualStack(name, ifName, ipv4, ipv6 string, signal, subflow bool) []byte {
	return []byte(fmt.Sprintf(`{
		"name": "%s",
		"type": "mptcp",
		"cniVersion": "1.0.0",
		"endpoints": {
			"signal": %t,
			"subflow": %t
		},
		"prevResult": {
			"interfaces": [
				{"name": "%s", "sandbox": "netns"}
			],
			"ips": [
				{
					"address": "%s",
					"interface": 0
				},
				{
					"address": "%s",
					"interface": 0
				}
			]
		}
	}`, name, signal, subflow, ifName, ipv4, ipv6))
}

func configForLimits(name, ifName, ip string, subflows, addAddrAccepted uint32) []byte {
	return []byte(fmt.Sprintf(`{
		"name": "%s",
		"type": "mptcp",
		"cniVersion": "1.0.0",
		"limits": {
			"subflows": %d,
			"addAddrAccepted": %d
		},
		"prevResult": {
			"interfaces": [
				{"name": "%s", "sandbox": "netns"}
			],
			"ips": [
				{
					"address": "%s",
					"interface": 0
				}
			]
		}
	}`, name, subflows, addAddrAccepted, ifName, ip))
}

func configForBoth(name, ifName, ip string, signal, subflow bool, subflows, addAddrAccepted uint32) []byte {
	return []byte(fmt.Sprintf(`{
		"name": "%s",
		"type": "mptcp",
		"cniVersion": "1.0.0",
		"endpoints": {
			"signal": %t,
			"subflow": %t
		},
		"limits": {
			"subflows": %d,
			"addAddrAccepted": %d
		},
		"prevResult": {
			"interfaces": [
				{"name": "%s", "sandbox": "netns"}
			],
			"ips": [
				{
					"address": "%s",
					"interface": 0
				}
			]
		}
	}`, name, signal, subflow, subflows, addAddrAccepted, ifName, ip))
}

var _ = Describe("mptcp plugin", func() {
	var originalNS ns.NetNS
	var targetNS ns.NetNS
	const IFName = "dummy0"

	BeforeEach(func() {
		var err error
		originalNS, err = testutils.NewNS()
		Expect(err).NotTo(HaveOccurred())

		targetNS, err = testutils.NewNS()
		Expect(err).NotTo(HaveOccurred())

		// Check if MPTCP path manager is available in the kernel
		err = targetNS.Do(func(ns.NetNS) error {
			_, err := netlink.GenlFamilyGet("mptcp_pm")
			return err
		})
		if err != nil {
			Skip("MPTCP path manager not available in kernel")
		}

		err = targetNS.Do(func(ns.NetNS) error {
			defer GinkgoRecover()
			la := netlink.NewLinkAttrs()
			la.Name = IFName
			err := netlink.LinkAdd(&netlink.Dummy{LinkAttrs: la})
			Expect(err).NotTo(HaveOccurred())

			link, err := netlinksafe.LinkByName(IFName)
			Expect(err).NotTo(HaveOccurred())

			addr, err := netlink.ParseAddr("10.0.0.2/24")
			Expect(err).NotTo(HaveOccurred())
			err = netlink.AddrAdd(link, addr)
			Expect(err).NotTo(HaveOccurred())

			addr6, err := netlink.ParseAddr("fd00::2/64")
			Expect(err).NotTo(HaveOccurred())
			err = netlink.AddrAdd(link, addr6)
			Expect(err).NotTo(HaveOccurred())

			err = netlink.LinkSetUp(link)
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
		conf := configForEndpoints("test", IFName, "10.0.0.2/24", true, true, false, false)
		args := &skel.CmdArgs{
			ContainerID: "dummy",
			Netns:       targetNS.Path(),
			IfName:      IFName,
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
			Expect(result.Interfaces[0].Name).To(Equal(IFName))
			Expect(result.IPs).To(HaveLen(1))
			Expect(result.IPs[0].Address.String()).To(Equal("10.0.0.2/24"))
			return nil
		})
		Expect(err).NotTo(HaveOccurred())
	})

	It("adds MPTCP endpoint for IPv4 with signal+subflow flags", func() {
		conf := configForEndpoints("test", IFName, "10.0.0.2/24", true, true, false, false)
		args := &skel.CmdArgs{
			ContainerID: "dummy",
			Netns:       targetNS.Path(),
			IfName:      IFName,
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

		// Verify endpoint was created
		err = targetNS.Do(func(ns.NetNS) error {
			defer GinkgoRecover()
			familyID, err := getMPTCPFamilyID()
			Expect(err).NotTo(HaveOccurred())

			endpoints, err := listEndpoints(familyID)
			Expect(err).NotTo(HaveOccurred())

			found := false
			for _, ep := range endpoints {
				if ep.Addr != nil && ep.Addr.String() == "10.0.0.2" {
					found = true
					Expect(ep.Flags).To(Equal(uint32(mptcpPMAddrFlagSignal | mptcpPMAddrFlagSubflow)))
					break
				}
			}
			Expect(found).To(BeTrue(), "expected MPTCP endpoint for 10.0.0.2")
			return nil
		})
		Expect(err).NotTo(HaveOccurred())
	})

	It("adds MPTCP endpoint for IPv6", func() {
		conf := configForEndpoints("test", IFName, "fd00::2/64", true, false, false, false)
		args := &skel.CmdArgs{
			ContainerID: "dummy",
			Netns:       targetNS.Path(),
			IfName:      IFName,
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
			familyID, err := getMPTCPFamilyID()
			Expect(err).NotTo(HaveOccurred())

			endpoints, err := listEndpoints(familyID)
			Expect(err).NotTo(HaveOccurred())

			found := false
			for _, ep := range endpoints {
				if ep.Addr != nil && ep.Addr.String() == "fd00::2" {
					found = true
					Expect(ep.Flags).To(Equal(uint32(mptcpPMAddrFlagSignal)))
					break
				}
			}
			Expect(found).To(BeTrue(), "expected MPTCP endpoint for fd00::2")
			return nil
		})
		Expect(err).NotTo(HaveOccurred())
	})

	It("adds MPTCP endpoints for dual-stack", func() {
		conf := configForEndpointsDualStack("test", IFName, "10.0.0.2/24", "fd00::2/64", true, true)
		args := &skel.CmdArgs{
			ContainerID: "dummy",
			Netns:       targetNS.Path(),
			IfName:      IFName,
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
			familyID, err := getMPTCPFamilyID()
			Expect(err).NotTo(HaveOccurred())

			endpoints, err := listEndpoints(familyID)
			Expect(err).NotTo(HaveOccurred())

			foundV4 := false
			foundV6 := false
			for _, ep := range endpoints {
				if ep.Addr == nil {
					continue
				}
				if ep.Addr.String() == "10.0.0.2" {
					foundV4 = true
				}
				if ep.Addr.String() == "fd00::2" {
					foundV6 = true
				}
			}
			Expect(foundV4).To(BeTrue(), "expected MPTCP endpoint for 10.0.0.2")
			Expect(foundV6).To(BeTrue(), "expected MPTCP endpoint for fd00::2")
			return nil
		})
		Expect(err).NotTo(HaveOccurred())
	})

	It("sets MPTCP limits", func() {
		conf := configForLimits("test", IFName, "10.0.0.2/24", 4, 4)
		args := &skel.CmdArgs{
			ContainerID: "dummy",
			Netns:       targetNS.Path(),
			IfName:      IFName,
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
			familyID, err := getMPTCPFamilyID()
			Expect(err).NotTo(HaveOccurred())

			subflows, addAddrAccepted, err := getLimits(familyID)
			Expect(err).NotTo(HaveOccurred())
			Expect(subflows).To(Equal(uint32(4)))
			Expect(addAddrAccepted).To(Equal(uint32(4)))
			return nil
		})
		Expect(err).NotTo(HaveOccurred())
	})

	It("configures both endpoints and limits", func() {
		conf := configForBoth("test", IFName, "10.0.0.2/24", true, true, 8, 8)
		args := &skel.CmdArgs{
			ContainerID: "dummy",
			Netns:       targetNS.Path(),
			IfName:      IFName,
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
			familyID, err := getMPTCPFamilyID()
			Expect(err).NotTo(HaveOccurred())

			// Check endpoint
			endpoints, err := listEndpoints(familyID)
			Expect(err).NotTo(HaveOccurred())
			found := false
			for _, ep := range endpoints {
				if ep.Addr != nil && ep.Addr.String() == "10.0.0.2" {
					found = true
					Expect(ep.Flags).To(Equal(uint32(mptcpPMAddrFlagSignal | mptcpPMAddrFlagSubflow)))
					break
				}
			}
			Expect(found).To(BeTrue(), "expected MPTCP endpoint for 10.0.0.2")

			// Check limits
			subflows, addAddrAccepted, err := getLimits(familyID)
			Expect(err).NotTo(HaveOccurred())
			Expect(subflows).To(Equal(uint32(8)))
			Expect(addAddrAccepted).To(Equal(uint32(8)))
			return nil
		})
		Expect(err).NotTo(HaveOccurred())
	})

	It("cmdDel removes endpoints", func() {
		conf := configForEndpoints("test", IFName, "10.0.0.2/24", true, true, false, false)
		args := &skel.CmdArgs{
			ContainerID: "dummy",
			Netns:       targetNS.Path(),
			IfName:      IFName,
			StdinData:   conf,
		}

		// Add first
		err := originalNS.Do(func(ns.NetNS) error {
			defer GinkgoRecover()
			_, _, err := testutils.CmdAddWithArgs(args, func() error {
				return cmdAdd(args)
			})
			Expect(err).NotTo(HaveOccurred())
			return nil
		})
		Expect(err).NotTo(HaveOccurred())

		// Delete
		err = originalNS.Do(func(ns.NetNS) error {
			defer GinkgoRecover()
			err := testutils.CmdDelWithArgs(args, func() error {
				return cmdDel(args)
			})
			Expect(err).NotTo(HaveOccurred())
			return nil
		})
		Expect(err).NotTo(HaveOccurred())

		// Verify endpoint is gone
		err = targetNS.Do(func(ns.NetNS) error {
			defer GinkgoRecover()
			familyID, err := getMPTCPFamilyID()
			Expect(err).NotTo(HaveOccurred())

			endpoints, err := listEndpoints(familyID)
			Expect(err).NotTo(HaveOccurred())

			for _, ep := range endpoints {
				if ep.Addr != nil && ep.Addr.String() == "10.0.0.2" {
					Fail("endpoint 10.0.0.2 should have been removed")
				}
			}
			return nil
		})
		Expect(err).NotTo(HaveOccurred())
	})

	It("cmdDel handles namespace already gone", func() {
		conf := configForEndpoints("test", IFName, "10.0.0.2/24", true, true, false, false)

		// Use a non-existent namespace path
		args := &skel.CmdArgs{
			ContainerID: "dummy",
			Netns:       "/var/run/netns/does-not-exist",
			IfName:      IFName,
			StdinData:   conf,
		}

		err := originalNS.Do(func(ns.NetNS) error {
			defer GinkgoRecover()
			err := testutils.CmdDelWithArgs(args, func() error {
				return cmdDel(args)
			})
			Expect(err).NotTo(HaveOccurred())
			return nil
		})
		Expect(err).NotTo(HaveOccurred())
	})

	It("cmdCheck verifies endpoints exist with correct flags", func() {
		conf := configForEndpoints("test", IFName, "10.0.0.2/24", true, true, false, false)
		args := &skel.CmdArgs{
			ContainerID: "dummy",
			Netns:       targetNS.Path(),
			IfName:      IFName,
			StdinData:   conf,
		}

		// Add first
		err := originalNS.Do(func(ns.NetNS) error {
			defer GinkgoRecover()
			_, _, err := testutils.CmdAddWithArgs(args, func() error {
				return cmdAdd(args)
			})
			Expect(err).NotTo(HaveOccurred())
			return nil
		})
		Expect(err).NotTo(HaveOccurred())

		// Check should pass
		err = originalNS.Do(func(ns.NetNS) error {
			defer GinkgoRecover()
			err := testutils.CmdCheckWithArgs(args, func() error {
				return cmdCheck(args)
			})
			Expect(err).NotTo(HaveOccurred())
			return nil
		})
		Expect(err).NotTo(HaveOccurred())
	})

	It("cmdCheck fails when endpoint is missing", func() {
		conf := configForEndpoints("test", IFName, "10.0.0.2/24", true, true, false, false)
		args := &skel.CmdArgs{
			ContainerID: "dummy",
			Netns:       targetNS.Path(),
			IfName:      IFName,
			StdinData:   conf,
		}

		// Don't add, just check -- should fail
		err := originalNS.Do(func(ns.NetNS) error {
			defer GinkgoRecover()
			err := testutils.CmdCheckWithArgs(args, func() error {
				return cmdCheck(args)
			})
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("not found"))
			return nil
		})
		Expect(err).NotTo(HaveOccurred())
	})

	It("cmdCheck verifies limits", func() {
		conf := configForLimits("test", IFName, "10.0.0.2/24", 6, 6)
		args := &skel.CmdArgs{
			ContainerID: "dummy",
			Netns:       targetNS.Path(),
			IfName:      IFName,
			StdinData:   conf,
		}

		// Add limits
		err := originalNS.Do(func(ns.NetNS) error {
			defer GinkgoRecover()
			_, _, err := testutils.CmdAddWithArgs(args, func() error {
				return cmdAdd(args)
			})
			Expect(err).NotTo(HaveOccurred())
			return nil
		})
		Expect(err).NotTo(HaveOccurred())

		// Check should pass
		err = originalNS.Do(func(ns.NetNS) error {
			defer GinkgoRecover()
			err := testutils.CmdCheckWithArgs(args, func() error {
				return cmdCheck(args)
			})
			Expect(err).NotTo(HaveOccurred())
			return nil
		})
		Expect(err).NotTo(HaveOccurred())
	})

	It("cmdAdd is idempotent", func() {
		conf := configForEndpoints("test", IFName, "10.0.0.2/24", true, true, false, false)
		args := &skel.CmdArgs{
			ContainerID: "dummy",
			Netns:       targetNS.Path(),
			IfName:      IFName,
			StdinData:   conf,
		}

		// Add once
		err := originalNS.Do(func(ns.NetNS) error {
			defer GinkgoRecover()
			_, _, err := testutils.CmdAddWithArgs(args, func() error {
				return cmdAdd(args)
			})
			Expect(err).NotTo(HaveOccurred())
			return nil
		})
		Expect(err).NotTo(HaveOccurred())

		// Add again -- should not error
		err = originalNS.Do(func(ns.NetNS) error {
			defer GinkgoRecover()
			_, _, err := testutils.CmdAddWithArgs(args, func() error {
				return cmdAdd(args)
			})
			Expect(err).NotTo(HaveOccurred())
			return nil
		})
		Expect(err).NotTo(HaveOccurred())
	})

	DescribeTable("endpoint flags",
		func(signal, subflow, backup, fullmesh bool, expectedFlags uint32) {
			conf := configForEndpoints("test", IFName, "10.0.0.2/24", signal, subflow, backup, fullmesh)
			args := &skel.CmdArgs{
				ContainerID: "dummy",
				Netns:       targetNS.Path(),
				IfName:      IFName,
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
				familyID, err := getMPTCPFamilyID()
				Expect(err).NotTo(HaveOccurred())

				endpoints, err := listEndpoints(familyID)
				Expect(err).NotTo(HaveOccurred())

				found := false
				for _, ep := range endpoints {
					if ep.Addr != nil && ep.Addr.String() == "10.0.0.2" {
						found = true
						Expect(ep.Flags).To(Equal(expectedFlags))
						break
					}
				}
				Expect(found).To(BeTrue())
				return nil
			})
			Expect(err).NotTo(HaveOccurred())
		},
		Entry("signal only", true, false, false, false, uint32(mptcpPMAddrFlagSignal)),
		Entry("subflow only", false, true, false, false, uint32(mptcpPMAddrFlagSubflow)),
		Entry("backup only", false, false, true, false, uint32(mptcpPMAddrFlagBackup)),
		Entry("fullmesh only", false, false, false, true, uint32(mptcpPMAddrFlagFullmesh)),
		Entry("signal+subflow", true, true, false, false, uint32(mptcpPMAddrFlagSignal|mptcpPMAddrFlagSubflow)),
		Entry("subflow+backup", false, true, true, false, uint32(mptcpPMAddrFlagSubflow|mptcpPMAddrFlagBackup)),
		Entry("signal+fullmesh", true, false, false, true, uint32(mptcpPMAddrFlagSignal|mptcpPMAddrFlagFullmesh)),
	)
})

var _ = Describe("config validation", func() {
	It("rejects config with no endpoints or limits", func() {
		conf := []byte(`{
			"name": "test",
			"type": "mptcp",
			"cniVersion": "1.0.0",
			"prevResult": {
				"interfaces": [{"name": "eth0", "sandbox": "netns"}],
				"ips": [{"address": "10.0.0.2/24", "interface": 0}]
			}
		}`)
		_, _, err := parseConf(conf)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("at least one"))
	})

	It("rejects endpoints with no flags set", func() {
		conf := []byte(`{
			"name": "test",
			"type": "mptcp",
			"cniVersion": "1.0.0",
			"endpoints": {},
			"prevResult": {
				"interfaces": [{"name": "eth0", "sandbox": "netns"}],
				"ips": [{"address": "10.0.0.2/24", "interface": 0}]
			}
		}`)
		_, _, err := parseConf(conf)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("no flags"))
	})

	It("accepts limits-only config", func() {
		conf := []byte(`{
			"name": "test",
			"type": "mptcp",
			"cniVersion": "1.0.0",
			"limits": {
				"subflows": 4
			},
			"prevResult": {
				"interfaces": [{"name": "eth0", "sandbox": "netns"}],
				"ips": [{"address": "10.0.0.2/24", "interface": 0}]
			}
		}`)
		parsed, result, err := parseConf(conf)
		Expect(err).NotTo(HaveOccurred())
		Expect(parsed.Endpoints).To(BeNil())
		Expect(parsed.Limits).NotTo(BeNil())
		Expect(*parsed.Limits.Subflows).To(Equal(uint32(4)))
		Expect(result.IPs).To(HaveLen(1))
	})

	It("accepts endpoints-only config", func() {
		conf := []byte(`{
			"name": "test",
			"type": "mptcp",
			"cniVersion": "1.0.0",
			"endpoints": {
				"signal": true
			},
			"prevResult": {
				"interfaces": [{"name": "eth0", "sandbox": "netns"}],
				"ips": [{"address": "10.0.0.2/24", "interface": 0}]
			}
		}`)
		parsed, _, err := parseConf(conf)
		Expect(err).NotTo(HaveOccurred())
		Expect(parsed.Endpoints).NotTo(BeNil())
		Expect(parsed.Limits).To(BeNil())
	})

	It("handles missing prevResult for DEL", func() {
		conf := []byte(`{
			"name": "test",
			"type": "mptcp",
			"cniVersion": "1.0.0",
			"endpoints": {
				"signal": true
			}
		}`)
		parsed, result, err := parseConf(conf)
		Expect(err).NotTo(HaveOccurred())
		Expect(parsed).NotTo(BeNil())
		Expect(result.IPs).To(BeEmpty())
	})
})
