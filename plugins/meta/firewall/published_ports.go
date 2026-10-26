// Copyright 2016 CNI authors
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

// This is a "meta-plugin". It reads in its own netconf, it does not create
// any network interface but just changes the network sysctl.

package main

import (
	"fmt"
	"net"
	"strconv"

	"github.com/coreos/go-iptables/iptables"

	current "github.com/containernetworking/cni/pkg/types/100"
	"github.com/containernetworking/plugins/pkg/utils"
)

type publishedPortMapping struct {
	HostPort      int    `json:"hostPort"`
	ContainerPort int    `json:"containerPort"`
	Protocol      string `json:"protocol"`
	HostIP        string `json:"hostIP,omitempty"`
}

type publishedPortRule struct {
	proto iptables.Protocol
	args  []string
}

func publishedPortRules(conf *FirewallNetConf, result *current.Result) ([]publishedPortRule, error) {
	if !conf.AllowPublishedPorts || conf.IngressPolicy != IngressPolicySameBridge {
		return nil, nil
	}
	if result == nil {
		return nil, fmt.Errorf("missing result for published ports")
	}
	var rules []publishedPortRule
	for _, mapping := range conf.RuntimeConfig.PortMappings {
		if mapping.HostPort < 1 || mapping.HostPort > 65535 || mapping.ContainerPort < 1 || mapping.ContainerPort > 65535 {
			return nil, fmt.Errorf("published port outside 1..65535")
		}
		if mapping.Protocol != "tcp" && mapping.Protocol != "udp" && mapping.Protocol != "sctp" {
			return nil, fmt.Errorf("unsupported published-port protocol %q", mapping.Protocol)
		}
		var hostIP net.IP
		if mapping.HostIP != "" {
			hostIP = net.ParseIP(mapping.HostIP)
			if hostIP == nil {
				return nil, fmt.Errorf("invalid published host IP %q", mapping.HostIP)
			}
		}
		for _, ip := range result.IPs {
			if ip == nil || ip.Interface == nil || *ip.Interface < 0 || *ip.Interface >= len(result.Interfaces) {
				continue
			}
			intf := result.Interfaces[*ip.Interface]
			if intf == nil || intf.Sandbox == "" {
				continue
			}
			if hostIP != nil && (hostIP.To4() == nil) != (ip.Address.IP.To4() == nil) {
				continue
			}
			if len(result.Interfaces) == 0 || result.Interfaces[0] == nil || result.Interfaces[0].Name == "" {
				return nil, fmt.Errorf("missing bridge interface")
			}
			bridge := result.Interfaces[0].Name
			common := []string{"-p", mapping.Protocol, "-m", "conntrack", "--ctstate", "DNAT", "--ctorigdstport", strconv.Itoa(mapping.HostPort)}
			if hostIP != nil && !hostIP.IsUnspecified() {
				common = append(common, "--ctorigdst", hostIP.String())
			}
			original := append([]string{"-o", bridge, "-d", ipString(ip.Address)}, common...)
			original = append(original, "--ctdir", "ORIGINAL", "--dport", strconv.Itoa(mapping.ContainerPort), "-j", "CNI-FORWARD")
			reply := append([]string{"-i", bridge, "-s", ipString(ip.Address)}, common...)
			reply = append(reply, "--ctdir", "REPLY", "--sport", strconv.Itoa(mapping.ContainerPort), "-j", "CNI-FORWARD")
			rules = append(rules, publishedPortRule{protoForIP(ip.Address), original}, publishedPortRule{protoForIP(ip.Address), reply})
		}
	}
	return rules, nil
}

func publishedPortChain(conf *FirewallNetConf, containerID string) string {
	return utils.MustFormatChainNameWithPrefix(conf.Name, containerID, "PP-")
}

func publishedPortJump(chain string) []string {
	return []string{"-m", "comment", "--comment", "CNI published ports", "-j", chain}
}

func setupPublishedPorts(conf *FirewallNetConf, result *current.Result, containerID string) error {
	rules, err := publishedPortRules(conf, result)
	if err != nil || len(rules) == 0 {
		return err
	}
	chain := publishedPortChain(conf, containerID)
	rollback := func(err error) error {
		_ = deletePublishedPorts(conf, containerID)
		return err
	}
	for _, proto := range []iptables.Protocol{iptables.ProtocolIPv4, iptables.ProtocolIPv6} {
		var familyRules [][]string
		for _, rule := range rules {
			if rule.proto == proto {
				familyRules = append(familyRules, rule.args)
			}
		}
		if len(familyRules) == 0 {
			continue
		}
		ipt, err := iptables.NewWithProtocol(proto)
		if err != nil {
			return rollback(err)
		}
		if err := utils.EnsureChain(ipt, "filter", chain); err != nil {
			return rollback(err)
		}
		for _, rule := range familyRules {
			if err := ipt.AppendUnique("filter", chain, rule...); err != nil {
				return rollback(err)
			}
		}
		// FORWARD's isolation jump is installed once; later bridge rules are
		// added inside the isolation chains, below this scoped entry point.
		if err := ensureFirstChainRule(ipt, "FORWARD", publishedPortJump(chain)); err != nil {
			return rollback(err)
		}
	}
	return nil
}

func deletePublishedPorts(conf *FirewallNetConf, containerID string) error {
	chain := publishedPortChain(conf, containerID)
	for _, proto := range []iptables.Protocol{iptables.ProtocolIPv4, iptables.ProtocolIPv6} {
		ipt, err := iptables.NewWithProtocol(proto)
		if err != nil {
			return err
		}
		if err := utils.DeleteRule(ipt, "filter", "FORWARD", publishedPortJump(chain)...); err != nil {
			return err
		}
		exists, err := ipt.ChainExists("filter", chain)
		if err != nil {
			return err
		}
		if !exists {
			continue
		}
		if err := ipt.ClearChain("filter", chain); err != nil {
			return err
		}
		if err := ipt.DeleteChain("filter", chain); err != nil {
			return err
		}
	}
	return nil
}

func checkPublishedPorts(conf *FirewallNetConf, result *current.Result, containerID string) error {
	rules, err := publishedPortRules(conf, result)
	if err != nil {
		return err
	}
	chain := publishedPortChain(conf, containerID)
	for _, rule := range rules {
		ipt, err := iptables.NewWithProtocol(rule.proto)
		if err != nil {
			return err
		}
		for _, check := range []struct {
			chain string
			args  []string
		}{{"FORWARD", publishedPortJump(chain)}, {chain, rule.args}} {
			exists, err := ipt.Exists("filter", check.chain, check.args...)
			if err != nil {
				return err
			}
			if !exists {
				return fmt.Errorf("missing published-port rule in %s", check.chain)
			}
		}
	}
	return nil
}
