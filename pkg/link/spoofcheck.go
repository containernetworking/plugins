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
	ifaceChain := sc.ifaceChain(bridgeTable)
	baseConfig.AddChain(ifaceChain)
	macChain := sc.macChain(bridgeTable, ifaceChain.Name)
	baseConfig.AddChain(macChain)

	if err := sc.configurer.Apply(baseConfig); err != nil {
		return fmt.Errorf("failed to setup spoof-check: %v", err)
	}

	rulesConfig := nft.NewConfig()

	rulesConfig.FlushChain(ifaceChain)
	rulesConfig.FlushChain(macChain)

	rulesConfig.AddRule(sc.matchIfaceJumpToChainRule(baseBridgeChain, ifaceChain))
	rulesConfig.AddRule(sc.jumpToChainRule(ifaceChain, macChain))
	rulesConfig.AddRule(sc.matchMacRule(macChain))
	rulesConfig.AddRule(sc.dropRule(macChain))

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
	ifaceChain := sc.ifaceChain(bridgeTable)

	currentConfig, ifaceMatchRuleErr := sc.configurer.Read()
	if ifaceMatchRuleErr == nil {
		expectedRuleToFind := sc.matchIfaceJumpToChainRule(baseBridgeChain, ifaceChain)
		// It is safer to exclude the statement matching, avoiding cases where a current statement includes
		// additional default entries (e.g. counters).
		ruleToFindExcludingStatements := *expectedRuleToFind
		ruleToFindExcludingStatements.Expr = nil
		rules := currentConfig.LookupRule(&ruleToFindExcludingStatements)
		if len(rules) > 0 {
			c := nft.NewConfig()
			for _, rule := range rules {
				c.DeleteRule(rule)
			}
			if err := sc.configurer.Apply(c); err != nil {
				ifaceMatchRuleErr = fmt.Errorf("failed to delete iface match rule: %v", err)
			}
		} else {
			fmt.Fprintf(os.Stderr, "spoofcheck/teardown: unable to detect iface match rule for deletion: %+v", expectedRuleToFind)
		}
	}

	regularChainsConfig := nft.NewConfig()
	regularChainsConfig.DeleteChain(ifaceChain)
	regularChainsConfig.DeleteChain(sc.macChain(bridgeTable, ifaceChain.Name))

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
