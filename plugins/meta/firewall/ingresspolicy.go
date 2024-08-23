// Copyright 2022 CNI authors
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

// This is a sample chained plugin that supports multiple CNI versions. It
// parses prevResult according to the cniVersion
package main

import (
	"fmt"

	"github.com/coreos/go-iptables/iptables"

	types100 "github.com/containernetworking/cni/pkg/types/100"
	"github.com/containernetworking/plugins/pkg/utils"
)

func setupIngressPolicy(conf *FirewallNetConf, prevResult *types100.Result) error {
	switch conf.IngressPolicy {
	case "", IngressPolicyOpen:
		// NOP
		return nil
	case IngressPolicySameBridge:
		return setupIngressPolicySameBridge(conf, prevResult)
	default:
		return fmt.Errorf("unknown ingress policy: %q", conf.IngressPolicy)
	}
}

func setupIngressPolicySameBridge(conf *FirewallNetConf, prevResult *types100.Result) error {
	if len(prevResult.Interfaces) == 0 {
		return fmt.Errorf("interface needs to be set for ingress policy %q, make sure to chain \"firewall\" plugin with \"bridge\"",
			conf.IngressPolicy)
	}
	intf := prevResult.Interfaces[0]
	if intf == nil {
		return fmt.Errorf("got nil interface")
	}
	bridgeName := intf.Name
	if bridgeName == "" {
		return fmt.Errorf("got empty bridge name")
	}
	for _, iptProto := range findProtos(conf) {
		ipt, err := iptables.NewWithProtocol(iptProto)
		if err != nil {
			return err
		}
		if err := setupIsolationChains(ipt, bridgeName); err != nil {
			return err
		}
	}
	return nil
}

func teardownIngressPolicy(conf *FirewallNetConf) error {
	switch conf.IngressPolicy {
	case "", IngressPolicyOpen:
		// NOP
		return nil
	case IngressPolicySameBridge:
		// NOP
		//
		// We can't be sure whether conf.bridgeName is still in use by other containers.
		// So we do not remove the iptable rules that are created per bridge.
		return nil
	default:
		return fmt.Errorf("unknown ingress policy: %q", conf.IngressPolicy)
	}
}

const (
	filterTableName  = "filter"  // built-in
	forwardChainName = "FORWARD" // built-in
)

// setupIsolationChains executes the following iptables commands for isolating networks:
// ```
// iptables -N CNI-ISOLATION-STAGE-1
// iptables -N CNI-ISOLATION-STAGE-2
// # NOTE: "-j CNI-ISOLATION-STAGE-1" needs to be before "CNI-FORWARD" chain. So we use -I here.
// iptables -I FORWARD -j CNI-ISOLATION-STAGE-1
// iptables -A CNI-ISOLATION-STAGE-1 -i ${bridgeName} ! -o ${bridgeName} -j CNI-ISOLATION-STAGE-2
// iptables -A CNI-ISOLATION-STAGE-1 -j RETURN
// iptables -A CNI-ISOLATION-STAGE-2 -o ${bridgeName} -j DROP
// iptables -A CNI-ISOLATION-STAGE-2 -j RETURN
// ```
func setupIsolationChains(ipt *iptables.IPTables, bridgeName string) error {
	const (
		// Future version may support custom chain names
		stage1Chain = "CNI-ISOLATION-STAGE-1"
		stage2Chain = "CNI-ISOLATION-STAGE-2"
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
	if err := utils.InsertUnique(ipt, filterTableName, forwardChainName, jumpToStage1Prepend, jumpToStage1); err != nil {
		return err
	}

	// Commands:
	// ```
	// iptables -A CNI-ISOLATION-STAGE-1 -i ${bridgeName} ! -o ${bridgeName} -j CNI-ISOLATION-STAGE-2
	// iptables -A CNI-ISOLATION-STAGE-1 -j RETURN
	// ```
	stage1Bridge := withDefaultComment(isolationStage1BridgeRule(bridgeName, stage2Chain))
	// prepend = true because this needs to be before "-j RETURN"
	const stage1BridgePrepend = true
	if err := utils.InsertUnique(ipt, filterTableName, stage1Chain, stage1BridgePrepend, stage1Bridge); err != nil {
		return err
	}
	stage1Return := withDefaultComment([]string{"-j", "RETURN"})
	if err := utils.InsertUnique(ipt, filterTableName, stage1Chain, false, stage1Return); err != nil {
		return err
	}

	// Commands:
	// ```
	// iptables -A CNI-ISOLATION-STAGE-2 -o ${bridgeName} -j DROP
	// iptables -A CNI-ISOLATION-STAGE-2 -j RETURN
	// ```
	stage2Bridge := withDefaultComment(isolationStage2BridgeRule(bridgeName))
	// prepend = true because this needs to be before "-j RETURN"
	const stage2BridgePrepend = true
	if err := utils.InsertUnique(ipt, filterTableName, stage2Chain, stage2BridgePrepend, stage2Bridge); err != nil {
		return err
	}
	stage2Return := withDefaultComment([]string{"-j", "RETURN"})
	return utils.InsertUnique(ipt, filterTableName, stage2Chain, false, stage2Return)
}

func isolationStage1BridgeRule(bridgeName, stage2Chain string) []string {
	return []string{"-i", bridgeName, "!", "-o", bridgeName, "-j", stage2Chain}
}

func isolationStage2BridgeRule(bridgeName string) []string {
	return []string{"-o", bridgeName, "-j", "DROP"}
}

func withDefaultComment(rule []string) []string {
	defaultComment := "CNI firewall plugin rules (ingressPolicy: same-bridge)"
	return withComment(rule, defaultComment)
}

func withComment(rule []string, comment string) []string {
	return append(rule, []string{"-m", "comment", "--comment", comment}...)
}
