// Copyright 2026 CNI authors
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
	"strings"

	"github.com/coreos/go-iptables/iptables"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/containernetworking/plugins/pkg/testutils"
)

var _ = Describe("Firewall Ingress Policy Bridge Isolation & Cleanup Invariants", func() {
	var (
		originalNS ns.NetNS
		targetNSA  ns.NetNS
		targetNSB  ns.NetNS
	)

	BeforeEach(func() {
		var err error
		originalNS, err = testutils.NewNS()
		Expect(err).NotTo(HaveOccurred())

		targetNSA, err = testutils.NewNS()
		Expect(err).NotTo(HaveOccurred())

		targetNSB, err = testutils.NewNS()
		Expect(err).NotTo(HaveOccurred())
	})

	AfterEach(func() {
		if targetNSA != nil {
			Expect(targetNSA.Close()).To(Succeed())
			Expect(testutils.UnmountNS(targetNSA)).To(Succeed())
		}
		if targetNSB != nil {
			Expect(targetNSB.Close()).To(Succeed())
			Expect(testutils.UnmountNS(targetNSB)).To(Succeed())
		}
		if originalNS != nil {
			Expect(originalNS.Close()).To(Succeed())
			Expect(testutils.UnmountNS(originalNS)).To(Succeed())
		}
	})

	makeBridgeFirewallConf := func(bridgeName, ingressPolicy, ip string) []byte {
		return []byte(fmt.Sprintf(`{
			"cniVersion": "1.0.0",
			"name": "test-firewall-net",
			"type": "firewall",
			"backend": "iptables",
			"ingressPolicy": "%s",
			"prevResult": {
				"cniVersion": "1.0.0",
				"interfaces": [
					{"name": "%s"}
				],
				"ips": [
					{
						"version": "4",
						"address": "%s",
						"interface": 0
					}
				]
			}
		}`, ingressPolicy, bridgeName, ip))
	}

	findStage1DropRule := func(rules []string, bridgeName string) bool {
		targetMatch := fmt.Sprintf("-i %s -o %s", bridgeName, bridgeName)
		for _, rule := range rules {
			if strings.Contains(rule, targetMatch) && strings.Contains(rule, "-j DROP") {
				return true
			}
		}
		return false
	}

	It("demonstrates isolation drop rule contamination and permanent leak across ADD/DEL cycles", func() {
		bridgeName := "cni-test-br0"

		confContainerA := makeBridgeFirewallConf(bridgeName, "same-bridge", "10.88.0.2/24")
		confContainerB := makeBridgeFirewallConf(bridgeName, "isolated", "10.88.0.3/24")

		argsA := &skel.CmdArgs{
			ContainerID: "container-a-samebridge",
			Netns:       targetNSA.Path(),
			IfName:      "eth0",
			StdinData:   confContainerA,
		}

		argsB := &skel.CmdArgs{
			ContainerID: "container-b-isolated",
			Netns:       targetNSB.Path(),
			IfName:      "eth0",
			StdinData:   confContainerB,
		}

		err := originalNS.Do(func(ns.NetNS) error {
			defer GinkgoRecover()

			ipt, err := iptables.NewWithProtocol(iptables.ProtocolIPv4)
			Expect(err).NotTo(HaveOccurred())

			// Step 1: Add Container A with 'same-bridge'
			_, _, err = testutils.CmdAdd(targetNSA.Path(), argsA.ContainerID, "eth0", confContainerA, func() error {
				return cmdAdd(argsA)
			})
			Expect(err).NotTo(HaveOccurred())

			// Verify Stage 1 rules after Container A ADD:
			// Must NOT have DROP rule for intra-bridge traffic
			rulesStage1A, err := ipt.List("filter", "CNI-ISOLATION-STAGE-1")
			Expect(err).NotTo(HaveOccurred())
			Expect(findStage1DropRule(rulesStage1A, bridgeName)).To(BeFalse(),
				"Container A with same-bridge should not have intra-bridge DROP rule")

			// Step 2: Add Container B with 'isolated' on the SAME bridge
			_, _, err = testutils.CmdAdd(targetNSB.Path(), argsB.ContainerID, "eth0", confContainerB, func() error {
				return cmdAdd(argsB)
			})
			Expect(err).NotTo(HaveOccurred())

			// Verify Stage 1 rules after Container B ADD:
			// Container B prepends the intra-bridge DROP rule
			rulesStage1B, err := ipt.List("filter", "CNI-ISOLATION-STAGE-1")
			Expect(err).NotTo(HaveOccurred())
			Expect(findStage1DropRule(rulesStage1B, bridgeName)).To(BeTrue(),
				"Container B with isolated installs intra-bridge DROP rule")

			// Step 3: Delete Container B (isolated)
			err = testutils.CmdDel(targetNSB.Path(), argsB.ContainerID, "eth0", func() error {
				return cmdDel(argsB)
			})
			Expect(err).NotTo(HaveOccurred())

			// CRITICAL INVARIANT CHECK 1:
			// Once Container B is deleted, its DROP rule should be removed.
			// In the current implementation, teardownIngressPolicy is a NOP, so the rule LEAKS.
			rulesAfterDelB, err := ipt.List("filter", "CNI-ISOLATION-STAGE-1")
			Expect(err).NotTo(HaveOccurred())
			hasLeakedDropRule := findStage1DropRule(rulesAfterDelB, bridgeName)

			// Step 4: Delete Container A (same-bridge)
			err = testutils.CmdDel(targetNSA.Path(), argsA.ContainerID, "eth0", func() error {
				return cmdDel(argsA)
			})
			Expect(err).NotTo(HaveOccurred())

			// CRITICAL INVARIANT CHECK 2:
			// When all containers on the bridge are deleted, no orphaned DROP rules should remain.
			rulesAfterAllDel, err := ipt.List("filter", "CNI-ISOLATION-STAGE-1")
			Expect(err).NotTo(HaveOccurred())
			hasOrphanedRule := findStage1DropRule(rulesAfterAllDel, bridgeName)

			// Document invariant violation status
			Expect(hasLeakedDropRule).To(BeTrue(), "Confirms DROP rule leaks after Container B DEL")
			Expect(hasOrphanedRule).To(BeTrue(), "Confirms DROP rule remains orphaned when 0 containers remain")

			return nil
		})
		Expect(err).NotTo(HaveOccurred())
	})
})
