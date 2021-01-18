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

package main

import (
	"fmt"

	"github.com/containernetworking/plugins/pkg/utils"
	"github.com/coreos/go-iptables/iptables"
)

const (
	filterTableName        = "filter"  // built-in
	forwardChainName       = "FORWARD" // built-in
	defaultStage1ChainName = "CNI-ISOLATION-STAGE-1"
	defaultStage2ChainName = "CNI-ISOLATION-STAGE-2"
)

// setupChain executes the following iptables commands:
// ```
// iptables -N CNI-ISOLATION-STAGE-1
// iptables -N CNI-ISOLATION-STAGE-2
// # NOTE: "-j CNI-ISOLATION-STAGE-1" needs to be before "CNI-FORWARD" created by CNI firewall plugin. So we use -I here.
// iptables -I FORWARD -j CNI-ISOLATION-STAGE-1
// iptables -A CNI-ISOLATION-STAGE-1 -i ${bridgeName} ! -o ${bridgeName} -j CNI-ISOLATION-STAGE-2
// iptables -A CNI-ISOLATION-STAGE-1 -j RETURN
// iptables -A CNI-ISOLATION-STAGE-2 -o ${bridgeName} -j DROP
// iptables -A CNI-ISOLATION-STAGE-2 -j RETURN
// ```
func setupChain(ipt *iptables.IPTables, bridgeName string) error {
	const (
		// Future version may support custom chain names
		stage1Chain = defaultStage1ChainName
		stage2Chain = defaultStage2ChainName
	)
	// Commands:
	// ```
	// iptables -N CNI-ISOLATION-STAGE-1
	// iptables -N CNI-ISOLATION-STAGE-2
	// ```
	for _, chain := range []string{stage1Chain, stage2Chain} {
		if err := utils.EnsureChain(ipt, filterTableName, chain); err != nil {
			return err
		}
	}

	// Commands:
	// ```
	// iptables -I FORWARD -j CNI-ISOLATION-STAGE-1
	// ```
	jumpToStage1 := withDefaultComment([]string{"-j", stage1Chain})
	//  NOTE: "-j CNI-ISOLATION-STAGE-1" needs to be before "CNI-FORWARD" created by CNI firewall plugin.
	// So we specify prepend = true .
	const jumpToStage1Prepend = true
	if err := insertUnique(ipt, filterTableName, forwardChainName, jumpToStage1Prepend, jumpToStage1); err != nil {
		return err
	}

	// Commands:
	// ```
	// iptables -A CNI-ISOLATION-STAGE-1 -i ${bridgeName} ! -o ${bridgeName} -j CNI-ISOLATION-STAGE-2
	// iptables -A CNI-ISOLATION-STAGE-1 -j RETURN
	// ```
	stage1Bridge := withDefaultComment(stage1BridgeRule(bridgeName, stage2Chain))
	// prepend = true because this needs to be before "-j RETURN"
	const stage1BridgePrepend = true
	if err := insertUnique(ipt, filterTableName, stage1Chain, stage1BridgePrepend, stage1Bridge); err != nil {
		return err
	}
	stage1Return := withDefaultComment([]string{"-j", "RETURN"})
	if err := insertUnique(ipt, filterTableName, stage1Chain, false, stage1Return); err != nil {
		return err
	}

	// Commands:
	// ```
	// iptables -A CNI-ISOLATION-STAGE-2 -o ${bridgeName} -j DROP
	// iptables -A CNI-ISOLATION-STAGE-2 -j RETURN
	// ```
	stage2Bridge := withDefaultComment(stage2BridgeRule(bridgeName))
	// prepend = true because this needs to be before "-j RETURN"
	const stage2BridgePrepend = true
	if err := insertUnique(ipt, filterTableName, stage2Chain, stage2BridgePrepend, stage2Bridge); err != nil {
		return err
	}
	stage2Return := withDefaultComment([]string{"-j", "RETURN"})
	if err := insertUnique(ipt, filterTableName, stage2Chain, false, stage2Return); err != nil {
		return err
	}

	return nil
}

func stage1BridgeRule(bridgeName, stage2Chain string) []string {
	return []string{"-i", bridgeName, "!", "-o", bridgeName, "-j", stage2Chain}
}

func stage2BridgeRule(bridgeName string) []string {
	return []string{"-o", bridgeName, "-j", "DROP"}
}

func withDefaultComment(rule []string) []string {
	defaultComment := fmt.Sprintf("CNI %s plugin rules", PluginName)
	return withComment(rule, defaultComment)
}

func withComment(rule []string, comment string) []string {
	return append(rule, []string{"-m", "comment", "--comment", comment}...)
}

// insertUnique will add a rule to a chain if it does not already exist.
// By default the rule is appended, unless prepend is true.
//
// insertUnique was taken from https://github.com/containernetworking/plugins/blob/v0.9.0/plugins/meta/portmap/chain.go#L104-L120
func insertUnique(ipt *iptables.IPTables, table, chain string, prepend bool, rule []string) error {
	exists, err := ipt.Exists(table, chain, rule...)
	if err != nil {
		return err
	}
	if exists {
		return nil
	}

	if prepend {
		return ipt.Insert(table, chain, 1, rule...)
	} else {
		return ipt.Append(table, chain, rule...)
	}
}
