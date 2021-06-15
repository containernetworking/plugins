// Copyright 2021 CNI authors
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

package link_test

import (
	"fmt"
	"github.com/networkplumbing/go-nft/nft"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/containernetworking/plugins/pkg/link"
)

var _ = Describe("spoofcheck", func() {
	iface := "net0"
	mac := "02:00:00:00:12:34"
	id := "container99-net1"

	Context("setup", func() {
		It("succeeds", func() {
			action := actionStub{}
			sc := link.NewSpoofCheckerWithCustomActions(iface, mac, id, action.applyConfigStub, nil)
			Expect(sc.Setup()).To(Succeed())

			assertExpectedTableAndChainsInSetupConfig(action)
			assertExpectedRulesInSetupConfig(action)
		})

		It("fails to setup config when 1st apply is unsuccessful (declare table and chains)", func() {
			action := actionStub{failFirstApplyConfig: true}
			sc := link.NewSpoofCheckerWithCustomActions(iface, mac, id, action.applyConfigStub, nil)
			Expect(sc.Setup()).To(MatchError("failed to setup spoof-check: " + errorFirstApplyText))
		})

		It("fails to setup config when 2nd apply is unsuccessful (flush and add the rules)", func() {
			action := actionStub{failSecondApplyConfig: true}
			sc := link.NewSpoofCheckerWithCustomActions(iface, mac, id, action.applyConfigStub, nil)
			Expect(sc.Setup()).To(MatchError("failed to setup spoof-check: " + errorSecondApplyText))
		})
	})

	Context("teardown", func() {
		It("succeeds", func() {
			existingConfig := nft.NewConfig()
			existingConfig.FromJSON([]byte(rowConfigWithRulesOnly()))
			action := actionStub{readConfig: existingConfig}

			sc := link.NewSpoofCheckerWithCustomActions("", "", id, action.applyConfigStub, action.readConfigStub)
			Expect(sc.Teardown()).To(Succeed())

			assertExpectedBaseChainRuleDeletionInTeardownConfig(action)
			assertExpectedRegularChainsDeletionInTeardownConfig(action)
		})

		It("fails, 1st apply is unsuccessful (delete iface match rule)", func() {
			config := nft.NewConfig()
			config.FromJSON([]byte(rowConfigWithRulesOnly()))
			action := actionStub{applyConfig: []*nft.Config{config}, readConfig: config, failFirstApplyConfig: true}
			sc := link.NewSpoofCheckerWithCustomActions("", "", id, action.applyConfigStub, action.readConfigStub)
			Expect(sc.Teardown()).To(MatchError(fmt.Sprintf(
				"failed to teardown spoof-check: failed to delete iface match rule: %s, <nil>", errorFirstApplyText,
			)))
		})

		It("fails, read current config is unsuccessful", func() {
			config := nft.NewConfig()
			config.FromJSON([]byte(rowConfigWithRulesOnly()))
			action := actionStub{applyConfig: []*nft.Config{config}, readConfig: config, failReadConfig: true}
			sc := link.NewSpoofCheckerWithCustomActions("", "", id, action.applyConfigStub, action.readConfigStub)
			Expect(sc.Teardown()).To(MatchError(fmt.Sprintf(
				"failed to teardown spoof-check: %s, <nil>", errorReadText,
			)))
		})

		It("fails, 2nd apply is unsuccessful (delete the regular chains)", func() {
			config := nft.NewConfig()
			config.FromJSON([]byte(rowConfigWithRulesOnly()))
			action := actionStub{applyConfig: []*nft.Config{config}, readConfig: config, failSecondApplyConfig: true}
			sc := link.NewSpoofCheckerWithCustomActions("", "", id, action.applyConfigStub, action.readConfigStub)
			Expect(sc.Teardown()).To(MatchError(fmt.Sprintf(
				"failed to teardown spoof-check: <nil>, failed to delete regular chains: %s", errorSecondApplyText,
			)))
		})

		It("fails, both applies are unsuccessful", func() {
			config := nft.NewConfig()
			config.FromJSON([]byte(rowConfigWithRulesOnly()))
			action := actionStub{
				applyConfig:           []*nft.Config{config},
				readConfig:            config,
				failFirstApplyConfig:  true,
				failSecondApplyConfig: true,
			}
			sc := link.NewSpoofCheckerWithCustomActions("", "", id, action.applyConfigStub, action.readConfigStub)
			Expect(sc.Teardown()).To(MatchError(fmt.Sprintf(
				"failed to teardown spoof-check: "+
					"failed to delete iface match rule: %s, "+
					"failed to delete regular chains: %s",
				errorFirstApplyText, errorSecondApplyText,
			)))
		})
	})
})

func assertExpectedRegularChainsDeletionInTeardownConfig(action actionStub) {
	deleteRegularChainRulesJsonConfig, err := action.applyConfig[1].ToJSON()
	ExpectWithOffset(1, err).NotTo(HaveOccurred())

	expectedDeleteRegularChainRulesJsonConfig := `
			{"nftables": [
				{"delete": {"chain": {
					"family": "bridge",
					"table": "nat",
					"name": "cni-br-iface-container99-net1"
				}}},
				{"delete": {"chain": {
					"family": "bridge",
					"table": "nat",
					"name": "cni-br-iface-container99-net1-mac"
				}}}
			]}`

	ExpectWithOffset(1, string(deleteRegularChainRulesJsonConfig)).To(MatchJSON(expectedDeleteRegularChainRulesJsonConfig))
}

func assertExpectedBaseChainRuleDeletionInTeardownConfig(action actionStub) {
	deleteBaseChainRuleJsonConfig, err := action.applyConfig[0].ToJSON()
	Expect(err).NotTo(HaveOccurred())

	expectedDeleteIfaceMatchRuleJsonConfig := `
            {"nftables": [
				{"delete": {"rule": {
					"family": "bridge",
					"table": "nat",
					"chain": "PREROUTING",
					"expr": [
						{"match": {
							"op": "==",
							"left": {"meta": {"key": "iifname"}},
							"right": "net0"
						}},
						{"jump": {"target": "cni-br-iface-container99-net1"}}
					],
					"comment": "macspoofchk-container99-net1"
				}}}
			]}`
	Expect(string(deleteBaseChainRuleJsonConfig)).To(MatchJSON(expectedDeleteIfaceMatchRuleJsonConfig))
}

func rowConfigWithRulesOnly() string {
	return `
            {"nftables":[
                {"rule":{"family":"bridge","table":"nat","chain":"PREROUTING",
                    "expr":[
                        {"match":{"op":"==","left":{"meta":{"key":"iifname"}},"right":"net0"}},
                        {"jump":{"target":"cni-br-iface-container99-net1"}}
                    ],
                    "comment":"macspoofchk-container99-net1"}},
                {"rule":{"family":"bridge","table":"nat","chain":"cni-br-iface-container99-net1",
                    "expr":[
                        {"jump":{"target":"cni-br-iface-container99-net1-mac"}}
                    ],
                    "comment":"macspoofchk-container99-net1"}},
                {"rule":{"family":"bridge","table":"nat","chain":"cni-br-iface-container99-net1-mac",
                    "expr":[
                        {"match":{
                            "op":"==",
                            "left":{"payload":{"protocol":"ether","field":"saddr"}},
                            "right":"02:00:00:00:12:34"
                        }},
                        {"return":null}
                    ],
                    "comment":"macspoofchk-container99-net1"}},
                {"rule":{"family":"bridge","table":"nat","chain":"cni-br-iface-container99-net1-mac",
                    "expr":[{"drop":null}],
                    "index":0,
                    "comment":"macspoofchk-container99-net1"}}
            ]}`
}

func assertExpectedTableAndChainsInSetupConfig(action actionStub) {
	config := action.applyConfig[0]
	jsonConfig, err := config.ToJSON()
	ExpectWithOffset(1, err).NotTo(HaveOccurred())

	expectedConfig := `
        {"nftables": [
            {"table": {"family": "bridge", "name": "nat"}},
            {"chain": {
                "family": "bridge",
                "table": "nat",
                "name": "PREROUTING",
                "type": "filter",
                "hook": "prerouting",
                "prio": -300,
                "policy": "accept"
            }},
            {"chain": {
                "family": "bridge",
                "table": "nat",
                "name": "cni-br-iface-container99-net1"
            }},
            {"chain": {
                "family": "bridge",
                "table": "nat",
                "name": "cni-br-iface-container99-net1-mac"
            }}
        ]}`
	ExpectWithOffset(1, string(jsonConfig)).To(MatchJSON(expectedConfig))
}

func assertExpectedRulesInSetupConfig(action actionStub) {
	config := action.applyConfig[1]
	jsonConfig, err := config.ToJSON()
	ExpectWithOffset(1, err).NotTo(HaveOccurred())

	expectedConfig := `
            {"nftables":[
                {"flush":{"chain":{"family":"bridge","table":"nat","name":"cni-br-iface-container99-net1"}}},
                {"flush":{"chain":{"family":"bridge","table":"nat","name":"cni-br-iface-container99-net1-mac"}}},
                {"rule":{"family":"bridge","table":"nat","chain":"PREROUTING",
                    "expr":[
                        {"match":{"op":"==","left":{"meta":{"key":"iifname"}},"right":"net0"}},
                        {"jump":{"target":"cni-br-iface-container99-net1"}}
                    ],
                    "comment":"macspoofchk-container99-net1"}},
                {"rule":{"family":"bridge","table":"nat","chain":"cni-br-iface-container99-net1",
                    "expr":[
                        {"jump":{"target":"cni-br-iface-container99-net1-mac"}}
                    ],
                    "comment":"macspoofchk-container99-net1"}},
                {"rule":{"family":"bridge","table":"nat","chain":"cni-br-iface-container99-net1-mac",
                    "expr":[
                        {"match":{
                            "op":"==",
                            "left":{"payload":{"protocol":"ether","field":"saddr"}},
                            "right":"02:00:00:00:12:34"
                        }},
                        {"return":null}
                    ],
                    "comment":"macspoofchk-container99-net1"}},
                {"rule":{"family":"bridge","table":"nat","chain":"cni-br-iface-container99-net1-mac",
                    "expr":[{"drop":null}],
                    "index":0,
                    "comment":"macspoofchk-container99-net1"}}
            ]}`
	ExpectWithOffset(1, string(jsonConfig)).To(MatchJSON(expectedConfig))
}

const (
	errorFirstApplyText  = "1st apply failed"
	errorSecondApplyText = "2nd apply failed"
	errorReadText        = "read failed"
)

type actionStub struct {
	applyConfig []*nft.Config
	readConfig  *nft.Config

	applyCounter int

	failFirstApplyConfig  bool
	failSecondApplyConfig bool
	failReadConfig        bool
}

func (a *actionStub) applyConfigStub(c *nft.Config) error {
	a.applyCounter++
	if a.failFirstApplyConfig && a.applyCounter == 1 {
		return fmt.Errorf(errorFirstApplyText)
	}
	if a.failSecondApplyConfig && a.applyCounter == 2 {
		return fmt.Errorf(errorSecondApplyText)
	}
	a.applyConfig = append(a.applyConfig, c)
	return nil
}

func (a *actionStub) readConfigStub() (*nft.Config, error) {
	if a.failReadConfig {
		return nil, fmt.Errorf(errorReadText)
	}
	return a.readConfig, nil
}
