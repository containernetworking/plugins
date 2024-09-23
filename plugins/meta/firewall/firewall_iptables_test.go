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
	"encoding/json"
	"fmt"
	"strings"

	"github.com/coreos/go-iptables/iptables"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/vishvananda/netlink"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	types040 "github.com/containernetworking/cni/pkg/types/040"
	current "github.com/containernetworking/cni/pkg/types/100"
	"github.com/containernetworking/cni/pkg/version"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/containernetworking/plugins/pkg/testutils"
)

func findChains(chains []string) (bool, bool) {
	var foundAdmin, foundPriv bool
	for _, ch := range chains {
		if ch == "CNI-ADMIN" {
			foundAdmin = true
		} else if ch == "CNI-FORWARD" {
			foundPriv = true
		}
	}
	return foundAdmin, foundPriv
}

func findForwardJumpRules(rules []string) (bool, bool) {
	var foundAdmin, foundPriv bool
	for _, rule := range rules {
		if strings.Contains(rule, "-j CNI-ADMIN") {
			foundAdmin = true
		} else if strings.Contains(rule, "-j CNI-FORWARD") {
			foundPriv = true
		}
	}
	return foundAdmin, foundPriv
}

func findForwardAllowRules(rules []string, ip string) (bool, bool) {
	var foundOne, foundTwo bool
	for _, rule := range rules {
		if !strings.HasSuffix(rule, "-j ACCEPT") {
			continue
		}
		if strings.Contains(rule, fmt.Sprintf(" -s %s ", ip)) {
			foundOne = true
		} else if strings.Contains(rule, fmt.Sprintf(" -d %s ", ip)) && strings.Contains(rule, "RELATED,ESTABLISHED") {
			foundTwo = true
		}
	}
	return foundOne, foundTwo
}

func getPrevResult(bytes []byte) *current.Result {
	type TmpConf struct {
		types.NetConf
		RawPrevResult map[string]interface{} `json:"prevResult,omitempty"`
		PrevResult    *current.Result        `json:"-"`
	}

	conf := &TmpConf{}
	err := json.Unmarshal(bytes, conf)
	Expect(err).NotTo(HaveOccurred())
	if conf.RawPrevResult == nil {
		return nil
	}

	resultBytes, err := json.Marshal(conf.RawPrevResult)
	Expect(err).NotTo(HaveOccurred())
	res, err := version.NewResult(conf.CNIVersion, resultBytes)
	Expect(err).NotTo(HaveOccurred())
	prevResult, err := current.NewResultFromResult(res)
	Expect(err).NotTo(HaveOccurred())

	return prevResult
}

func validateFullRuleset(bytes []byte) {
	prevResult := getPrevResult(bytes)

	for _, ip := range prevResult.IPs {
		ipt, err := iptables.NewWithProtocol(protoForIP(ip.Address))
		Expect(err).NotTo(HaveOccurred())

		// Ensure chains
		chains, err := ipt.ListChains("filter")
		Expect(err).NotTo(HaveOccurred())
		foundAdmin, foundPriv := findChains(chains)
		Expect(foundAdmin).To(BeTrue())
		Expect(foundPriv).To(BeTrue())

		// Look for the FORWARD chain jump rules to our custom chains
		rules, err := ipt.List("filter", "FORWARD")
		Expect(err).NotTo(HaveOccurred())
		Expect(len(rules)).Should(BeNumerically(">", 1))
		_, foundPriv = findForwardJumpRules(rules)
		Expect(foundPriv).To(BeTrue())

		// Look for the allow rules in our custom FORWARD chain
		rules, err = ipt.List("filter", "CNI-FORWARD")
		Expect(err).NotTo(HaveOccurred())
		Expect(len(rules)).Should(BeNumerically(">", 1))
		foundAdmin, _ = findForwardJumpRules(rules)
		Expect(foundAdmin).To(BeTrue())

		// Look for the IP allow rules
		foundOne, foundTwo := findForwardAllowRules(rules, ipString(ip.Address))
		Expect(foundOne).To(BeTrue())
		Expect(foundTwo).To(BeTrue())
	}
}

func validateCleanedUp(bytes []byte) {
	prevResult := getPrevResult(bytes)

	for _, ip := range prevResult.IPs {
		ipt, err := iptables.NewWithProtocol(protoForIP(ip.Address))
		Expect(err).NotTo(HaveOccurred())

		// Our private and admin chains don't get cleaned up
		chains, err := ipt.ListChains("filter")
		Expect(err).NotTo(HaveOccurred())
		foundAdmin, foundPriv := findChains(chains)
		Expect(foundAdmin).To(BeTrue())
		Expect(foundPriv).To(BeTrue())

		// Look for the FORWARD chain jump rules to our custom chains
		rules, err := ipt.List("filter", "FORWARD")
		Expect(err).NotTo(HaveOccurred())
		_, foundPriv = findForwardJumpRules(rules)
		Expect(foundPriv).To(BeTrue())

		// Look for the allow rules in our custom FORWARD chain
		rules, err = ipt.List("filter", "CNI-FORWARD")
		Expect(err).NotTo(HaveOccurred())
		foundAdmin, _ = findForwardJumpRules(rules)
		Expect(foundAdmin).To(BeTrue())

		// Expect no IP address rules for this IP
		foundOne, foundTwo := findForwardAllowRules(rules, ipString(ip.Address))
		Expect(foundOne).To(BeFalse())
		Expect(foundTwo).To(BeFalse())
	}
}

func makeIptablesConf(ver string) []byte {
	return []byte(fmt.Sprintf(`{
		"name": "test",
		"type": "firewall",
		"backend": "iptables",
		"ifName": "dummy0",
		"cniVersion": "%s",
		"prevResult": {
			"cniVersion": "%s",
			"interfaces": [
				{"name": "dummy0"}
			],
			"ips": [
				{
					"version": "4",
					"address": "10.0.0.2/24",
					"interface": 0
				},
				{
					"version": "6",
					"address": "2001:db8:1:2::1/64",
					"interface": 0
				}
			]
		}
	}`, ver, ver))
}

var _ = Describe("firewall plugin iptables backend", func() {
	var originalNS, targetNS ns.NetNS
	const IFNAME string = "dummy0"

	BeforeEach(func() {
		// Create a new NetNS so we don't modify the host
		var err error
		originalNS, err = testutils.NewNS()
		Expect(err).NotTo(HaveOccurred())

		err = originalNS.Do(func(ns.NetNS) error {
			defer GinkgoRecover()

			linkAttrs := netlink.NewLinkAttrs()
			linkAttrs.Name = IFNAME
			err = netlink.LinkAdd(&netlink.Dummy{
				LinkAttrs: linkAttrs,
			})
			Expect(err).NotTo(HaveOccurred())
			_, err = netlink.LinkByName(IFNAME)
			Expect(err).NotTo(HaveOccurred())
			return nil
		})
		Expect(err).NotTo(HaveOccurred())

		targetNS, err = testutils.NewNS()
		Expect(err).NotTo(HaveOccurred())
	})

	AfterEach(func() {
		Expect(originalNS.Close()).To(Succeed())
		Expect(targetNS.Close()).To(Succeed())
	})

	// firewall plugin requires a prevResult and thus only supports 0.3.0
	// and later CNI versions
	for _, ver := range []string{"0.3.0", "0.3.1", "0.4.0", "1.0.0"} {
		// Redefine ver inside for scope so real value is picked up by each dynamically defined It()
		// See Gingkgo's "Patterns for dynamically generating tests" documentation.
		ver := ver

		It(fmt.Sprintf("[%s] passes prevResult through unchanged", ver), func() {
			fullConf := makeIptablesConf(ver)
			args := &skel.CmdArgs{
				ContainerID: "dummy",
				Netns:       targetNS.Path(),
				IfName:      IFNAME,
				StdinData:   fullConf,
			}

			err := originalNS.Do(func(ns.NetNS) error {
				defer GinkgoRecover()

				r, _, err := testutils.CmdAdd(targetNS.Path(), args.ContainerID, IFNAME, fullConf, func() error {
					return cmdAdd(args)
				})
				Expect(err).NotTo(HaveOccurred())

				result, err := current.GetResult(r)
				Expect(err).NotTo(HaveOccurred())

				Expect(result.Interfaces).To(HaveLen(1))
				Expect(result.Interfaces[0].Name).To(Equal(IFNAME))
				Expect(result.IPs).To(HaveLen(2))
				Expect(result.IPs[0].Address.String()).To(Equal("10.0.0.2/24"))
				Expect(result.IPs[1].Address.String()).To(Equal("2001:db8:1:2::1/64"))
				return nil
			})
			Expect(err).NotTo(HaveOccurred())
		})

		It(fmt.Sprintf("[%s] installs the right iptables rules on the host", ver), func() {
			fullConf := makeIptablesConf(ver)
			args := &skel.CmdArgs{
				ContainerID: "dummy",
				Netns:       targetNS.Path(),
				IfName:      IFNAME,
				StdinData:   fullConf,
			}

			err := originalNS.Do(func(ns.NetNS) error {
				defer GinkgoRecover()

				_, _, err := testutils.CmdAdd(targetNS.Path(), args.ContainerID, IFNAME, fullConf, func() error {
					return cmdAdd(args)
				})
				Expect(err).NotTo(HaveOccurred())

				validateFullRuleset(fullConf)

				// ensure creation is idempotent
				_, _, err = testutils.CmdAdd(targetNS.Path(), args.ContainerID, IFNAME, fullConf, func() error {
					return cmdAdd(args)
				})
				Expect(err).NotTo(HaveOccurred())

				return nil
			})
			Expect(err).NotTo(HaveOccurred())
		})

		It(fmt.Sprintf("[%s] correctly handles a custom IptablesAdminChainName", ver), func() {
			conf := []byte(fmt.Sprintf(`{
				"name": "test",
				"type": "firewall",
				"backend": "iptables",
				"ifName": "dummy0",
				"cniVersion": "%s",
				"iptablesAdminChainName": "CNI-foobar",
				"prevResult": {
					"cniVersion": "%s",
					"interfaces": [
						{"name": "dummy0"}
					],
					"ips": [
						{
							"version": "4",
							"address": "10.0.0.2/24",
							"interface": 0
						},
						{
							"version": "6",
							"address": "2001:db8:1:2::1/64",
							"interface": 0
						}
					]
				}
			}`, ver, ver))

			args := &skel.CmdArgs{
				ContainerID: "dummy",
				Netns:       targetNS.Path(),
				IfName:      IFNAME,
				StdinData:   conf,
			}

			err := originalNS.Do(func(ns.NetNS) error {
				defer GinkgoRecover()

				_, _, err := testutils.CmdAdd(targetNS.Path(), args.ContainerID, IFNAME, conf, func() error {
					return cmdAdd(args)
				})
				Expect(err).NotTo(HaveOccurred())

				var ipt *iptables.IPTables
				for _, proto := range []iptables.Protocol{iptables.ProtocolIPv4, iptables.ProtocolIPv6} {
					ipt, err = iptables.NewWithProtocol(proto)
					Expect(err).NotTo(HaveOccurred())

					// Ensure custom admin chain name
					chains, err := ipt.ListChains("filter")
					Expect(err).NotTo(HaveOccurred())
					var foundAdmin bool
					for _, ch := range chains {
						if ch == "CNI-foobar" {
							foundAdmin = true
						}
					}
					Expect(foundAdmin).To(BeTrue())
				}

				return nil
			})
			Expect(err).NotTo(HaveOccurred())
		})

		It(fmt.Sprintf("[%s] installs iptables rules, checks rules, then cleans up on delete", ver), func() {
			fullConf := makeIptablesConf(ver)
			args := &skel.CmdArgs{
				ContainerID: "dummy",
				Netns:       targetNS.Path(),
				IfName:      IFNAME,
				StdinData:   fullConf,
			}

			err := originalNS.Do(func(ns.NetNS) error {
				defer GinkgoRecover()

				r, _, err := testutils.CmdAddWithArgs(args, func() error {
					return cmdAdd(args)
				})
				Expect(err).NotTo(HaveOccurred())

				_, err = types040.GetResult(r)
				Expect(err).NotTo(HaveOccurred())

				if testutils.SpecVersionHasCHECK(ver) {
					err = testutils.CmdCheckWithArgs(args, func() error {
						return cmdCheck(args)
					})
					Expect(err).NotTo(HaveOccurred())
					validateFullRuleset(fullConf)
				}

				err = testutils.CmdDelWithArgs(args, func() error {
					return cmdDel(args)
				})
				Expect(err).NotTo(HaveOccurred())
				validateCleanedUp(fullConf)
				return nil
			})
			Expect(err).NotTo(HaveOccurred())
		})
	}
})
