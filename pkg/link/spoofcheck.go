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

package link

import (
	"fmt"
	"os"

	"github.com/networkplumbing/go-nft/nft"
	"github.com/networkplumbing/go-nft/nft/schema"
)

const (
	natTableName             = "nat"
	inetTableName            = "inet"
	postRoutingBaseChainName = "POSTROUTING"
)

type NftConfigurer interface {
	Apply(*nft.Config) error
	Read() (*nft.Config, error)
}

type SpoofChecker struct {
	iface      string
	macAddress string
	refID      string
	configurer NftConfigurer
}

type defaultNftConfigurer struct{}

func (dnc defaultNftConfigurer) Apply(cfg *nft.Config) error {
	return nft.ApplyConfig(cfg)
}

func (dnc defaultNftConfigurer) Read() (*nft.Config, error) {
	return nft.ReadConfig()
}

func NewSpoofChecker(iface, macAddress, refID string) *SpoofChecker {
	return NewSpoofCheckerWithConfigurer(iface, macAddress, refID, defaultNftConfigurer{})
}

func NewSpoofCheckerWithConfigurer(iface, macAddress, refID string, configurer NftConfigurer) *SpoofChecker {
	return &SpoofChecker{iface, macAddress, refID, configurer}
}

// Setup applies nftables configuration to restrict traffic
// from the provided interface. Only traffic with the mentioned mac address
// is allowed to pass, all others are blocked.
// The configuration follows the format libvirt and ebtables implemented, allowing
// extensions to the rules in the future.
// refID is used to label the rules with a unique comment, identifying the rule-set.
//
// In order to take advantage of the nftables configuration change atomicity, the
// following steps are taken to apply the configuration:
// - Declare the table and chains (they will be created in case not present).
// - Apply the rules, while first flushing the iface/mac specific regular chain rules.
// Two transactions are used because the flush succeeds only if the table/chain it targets
// exists. This avoids the need to query the existing state and acting upon it (a raceful pattern).
// Although two transactions are taken place, only the 2nd one where the rules
// are added has a real impact on the system.
func (sc *SpoofChecker) Setup() error {
	baseConfig := nft.NewConfig()

	bridgeTable := schema.Table{Family: schema.FamilyBridge, Name: natTableName}
	baseConfig.AddTable(&bridgeTable)

	baseBridgeChain := sc.baseChain(bridgeTable)
	baseConfig.AddChain(baseBridgeChain)
	ifaceBridgeChain := sc.ifaceChain(bridgeTable)
	baseConfig.AddChain(ifaceBridgeChain)
	macBridgeChain := sc.macChain(bridgeTable, ifaceBridgeChain.Name)
	baseConfig.AddChain(macBridgeChain)

	ipTable := schema.Table{Family: schema.FamilyINET, Name: inetTableName}
	baseConfig.AddTable(&ipTable)

	baseIPChain := sc.baseChain(ipTable)
	baseConfig.AddChain(baseIPChain)
	ifaceIPChain := sc.ifaceChain(ipTable)
	baseConfig.AddChain(ifaceIPChain)
	macIPChain := sc.macChain(ipTable, ifaceIPChain.Name)
	baseConfig.AddChain(macIPChain)

	if err := sc.configurer.Apply(baseConfig); err != nil {
		return fmt.Errorf("failed to setup spoof-check: %v", err)
	}

	rulesConfig := nft.NewConfig()

	rulesConfig.FlushChain(ifaceBridgeChain)
	rulesConfig.FlushChain(macBridgeChain)

	rulesConfig.AddRule(sc.matchIfaceJumpToChainRule(baseBridgeChain, ifaceBridgeChain))
	rulesConfig.AddRule(sc.jumpToChainRule(ifaceBridgeChain, macBridgeChain))
	rulesConfig.AddRule(sc.matchMacRule(macBridgeChain))
	rulesConfig.AddRule(sc.dropRule(macBridgeChain))

	rulesConfig.FlushChain(ifaceIPChain)
	rulesConfig.FlushChain(macIPChain)

	rulesConfig.AddRule(sc.matchIfaceJumpToChainRule(baseIPChain, ifaceIPChain))
	rulesConfig.AddRule(sc.jumpToChainRule(ifaceIPChain, macIPChain))
	rulesConfig.AddRule(sc.matchMacRule(macIPChain))
	rulesConfig.AddRule(sc.dropRule(macIPChain))

	if err := sc.configurer.Apply(rulesConfig); err != nil {
		return fmt.Errorf("failed to setup spoof-check: %v", err)
	}

	return nil
}

// Teardown removes the interface and mac-address specific chains and their rules.
// The table and base-chain are expected to survive while the base-chain rule that matches the
// interface is removed.
func (sc *SpoofChecker) Teardown() error {
	bridgeTable := schema.Table{Family: schema.FamilyBridge, Name: natTableName}
	baseBridgeChain := sc.baseChain(bridgeTable)
	ifaceBridgeChain := sc.ifaceChain(bridgeTable)

	ipTable := schema.Table{Family: schema.FamilyINET, Name: inetTableName}
	baseIPChain := sc.baseChain(ipTable)
	ifaceIPChain := sc.ifaceChain(ipTable)

	currentConfig, ifaceMatchRuleErr := sc.configurer.Read()
	if ifaceMatchRuleErr == nil {
		expectedBridgeRuleToFind := sc.matchIfaceJumpToChainRule(baseBridgeChain, ifaceBridgeChain)
		expectedIPRuleToFind := sc.matchIfaceJumpToChainRule(baseIPChain, ifaceIPChain)
		// It is safer to exclude the statement matching, avoiding cases where a current statement includes
		// additional default entries (e.g. counters).
		ruleToFindExcludingStatements := *expectedBridgeRuleToFind
		ruleToFindExcludingStatements.Expr = nil
		rules := currentConfig.LookupRule(&ruleToFindExcludingStatements)
		ruleToFindExcludingStatements = *expectedIPRuleToFind
		ruleToFindExcludingStatements.Expr = nil
		rules = append(rules, currentConfig.LookupRule(&ruleToFindExcludingStatements)...)
		if len(rules) > 0 {
			c := nft.NewConfig()
			for _, rule := range rules {
				c.DeleteRule(rule)
			}
			if err := sc.configurer.Apply(c); err != nil {
				ifaceMatchRuleErr = fmt.Errorf("failed to delete iface match rule: %v", err)
			}
		} else {
			fmt.Fprintf(os.Stderr, "spoofcheck/teardown: unable to detect iface match rule for deletion: %+v", expectedBridgeRuleToFind)
		}
	}

	regularChainsConfig := nft.NewConfig()
	regularChainsConfig.DeleteChain(ifaceBridgeChain)
	regularChainsConfig.DeleteChain(sc.macChain(bridgeTable, ifaceBridgeChain.Name))
	regularChainsConfig.DeleteChain(ifaceIPChain)
	regularChainsConfig.DeleteChain(sc.macChain(ipTable, ifaceIPChain.Name))

	var regularChainsErr error
	if err := sc.configurer.Apply(regularChainsConfig); err != nil {
		regularChainsErr = fmt.Errorf("failed to delete regular chains: %v", err)
	}

	if ifaceMatchRuleErr != nil || regularChainsErr != nil {
		return fmt.Errorf("failed to teardown spoof-check: %v, %v", ifaceMatchRuleErr, regularChainsErr)
	}
	return nil
}

func (sc *SpoofChecker) matchIfaceJumpToChainRule(chain, toChain *schema.Chain) *schema.Rule {
	return &schema.Rule{
		Family: chain.Family,
		Table:  chain.Table,
		Chain:  chain.Name,
		Expr: []schema.Statement{
			{Match: &schema.Match{
				Op:    schema.OperEQ,
				Left:  schema.Expression{RowData: []byte(`{"meta":{"key":"oifname"}}`)},
				Right: schema.Expression{String: &sc.iface},
			}},
			{Verdict: schema.Verdict{Jump: &schema.ToTarget{Target: toChain.Name}}},
		},
		Comment: ruleComment(sc.refID),
	}
}

func (sc *SpoofChecker) jumpToChainRule(chain, toChain *schema.Chain) *schema.Rule {
	return &schema.Rule{
		Family: chain.Family,
		Table:  chain.Table,
		Chain:  chain.Name,
		Expr: []schema.Statement{
			{Verdict: schema.Verdict{Jump: &schema.ToTarget{Target: toChain.Name}}},
		},
		Comment: ruleComment(sc.refID),
	}
}

func (sc *SpoofChecker) matchMacRule(chain *schema.Chain) *schema.Rule {
	return &schema.Rule{
		Family: chain.Family,
		Table:  chain.Table,
		Chain:  chain.Name,
		Expr: []schema.Statement{
			{Match: &schema.Match{
				Op: schema.OperEQ,
				Left: schema.Expression{Payload: &schema.Payload{
					Protocol: schema.PayloadProtocolEther,
					Field:    schema.PayloadFieldEtherSAddr,
				}},
				Right: schema.Expression{String: &sc.macAddress},
			}},
			{Verdict: schema.Verdict{SimpleVerdict: schema.SimpleVerdict{Return: true}}},
		},
		Comment: ruleComment(sc.refID),
	}
}

func (sc *SpoofChecker) dropRule(chain *schema.Chain) *schema.Rule {
	macRulesIndex := nft.NewRuleIndex()
	return &schema.Rule{
		Family: chain.Family,
		Table:  chain.Table,
		Chain:  chain.Name,
		Index:  macRulesIndex.Next(),
		Expr: []schema.Statement{
			{Verdict: schema.Verdict{SimpleVerdict: schema.SimpleVerdict{Drop: true}}},
		},
		Comment: ruleComment(sc.refID),
	}
}

func (sc *SpoofChecker) baseChain(table schema.Table) *schema.Chain {
	chainPriority := -300
	return &schema.Chain{
		Family: table.Family,
		Table:  table.Name,
		Name:   postRoutingBaseChainName,
		Type:   schema.TypeFilter,
		Hook:   schema.HookPostRouting,
		Prio:   &chainPriority,
		Policy: schema.PolicyAccept,
	}
}

func (sc *SpoofChecker) ifaceChain(table schema.Table) *schema.Chain {
	ifaceChainName := "cni-br-iface-" + sc.refID
	return &schema.Chain{
		Family: table.Family,
		Table:  table.Name,
		Name:   ifaceChainName,
	}
}

func (sc *SpoofChecker) macChain(table schema.Table, ifaceChainName string) *schema.Chain {
	macChainName := ifaceChainName + "-mac"
	return &schema.Chain{
		Family: table.Family,
		Table:  table.Name,
		Name:   macChainName,
	}
}

func ruleComment(id string) string {
	const refIDPrefix = "macspoofchk-"
	return refIDPrefix + id
}
