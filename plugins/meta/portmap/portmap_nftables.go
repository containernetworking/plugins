// Copyright 2023 CNI authors
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
	"context"
	"fmt"
	"net"

	"github.com/danwinship/nftables"
)

const (
	tableName = "cni_hostport"

	hostIPHostPortsChain = "hostip_hostports"
	hostPortsChain       = "hostports"
	masqueradingChain    = "masquerading"
)

// The nftables portmap implementation is fairly similar to the iptables implementation:
// we add a rule for each mapping, with a comment containing a hash of the container ID,
// so that we can later reliably delete the rules we want. (This is important because in
// edge cases, it's possible the plugin might see "ADD container A with IP 192.168.1.3",
// followed by "ADD container B with IP 192.168.1.3" followed by "DEL container A with IP
// 192.168.1.3", and we need to make sure that the DEL causes us to delete the rule for
// container A, and not the rule for container B.) This iptables implementation actually
// uses a separate chain per container but there's not really any need for that...
//
// As with pkg/ip/ipmasq_nftables_linux.go, it would be more nftables-y to have a chain
// with a single rule doing a lookup against a map with an element per mapping, rather
// than having a chain with a rule per mapping. But there's no easy, non-racy way to say
// "delete the element 192.168.1.3 from the map, but only if it was added for container A,
// not if it was added for container B".

type portMapperNFTables struct {
	ipv4 nftables.Interface
	ipv6 nftables.Interface
}

// getPortMapNFT creates an nftables.Interface for port mapping for the IP family of ipn
func (pmNFT *portMapperNFTables) getPortMapNFT(ipv6 bool) nftables.Interface {
	if ipv6 {
		if pmNFT.ipv6 == nil {
			pmNFT.ipv6 = nftables.New(nftables.IPv6Family, tableName)
		}
		return pmNFT.ipv6
	}

	if pmNFT.ipv4 == nil {
		pmNFT.ipv4 = nftables.New(nftables.IPv4Family, tableName)
	}
	return pmNFT.ipv4
}

// forwardPorts establishes port forwarding to a given container IP.
// containerNet.IP can be either v4 or v6.
func (pmNFT *portMapperNFTables) forwardPorts(config *PortMapConf, containerNet net.IPNet) error {
	isV6 := (containerNet.IP.To4() == nil)
	nft := pmNFT.getPortMapNFT(isV6)
	var conditions []string
	if isV6 && config.ConditionsV6 != nil {
		conditions = *config.ConditionsV6
	} else if !isV6 && config.ConditionsV4 != nil {
		conditions = *config.ConditionsV4
	}

	tx := nftables.NewTransaction()

	// Ensure basic rule structure
	tx.Add(&nftables.Table{
		Comment: nftables.Optional("CNI portmap plugin"),
	})

	tx.Add(&nftables.Chain{
		Name: "hostports",
	})
	tx.Add(&nftables.Chain{
		Name: "hostip_hostports",
	})

	tx.Add(&nftables.Chain{
		Name:     "prerouting",
		Type:     nftables.Optional(nftables.NATType),
		Hook:     nftables.Optional(nftables.PreroutingHook),
		Priority: nftables.Optional(nftables.DNATPriority),
	})
	tx.Flush(&nftables.Chain{
		Name: "prerouting",
	})
	tx.Add(&nftables.Rule{
		Chain: "prerouting",
		Rule: nftables.Concat(
			conditions,
			"jump", hostIPHostPortsChain,
		),
	})
	tx.Add(&nftables.Rule{
		Chain: "prerouting",
		Rule: nftables.Concat(
			conditions,
			"jump", hostPortsChain,
		),
	})

	tx.Add(&nftables.Chain{
		Name: "output",
		Type: nftables.Optional(nftables.NATType),
		Hook: nftables.Optional(nftables.OutputHook),

		// DNATPriority is not allowed on OutputHook, even though the "dnat"
		// command is. Specify the numeric value instead...
		Priority: nftables.Optional(nftables.BaseChainPriority("-100")),
	})
	tx.Flush(&nftables.Chain{
		Name: "output",
	})
	tx.Add(&nftables.Rule{
		Chain: "output",
		Rule: nftables.Concat(
			conditions,
			"jump", hostIPHostPortsChain,
		),
	})
	tx.Add(&nftables.Rule{
		Chain: "output",
		Rule: nftables.Concat(
			conditions,
			"fib daddr type local",
			"jump", hostPortsChain,
		),
	})

	if *config.SNAT {
		tx.Add(&nftables.Chain{
			Name:     masqueradingChain,
			Type:     nftables.Optional(nftables.NATType),
			Hook:     nftables.Optional(nftables.PostroutingHook),
			Priority: nftables.Optional(nftables.SNATPriority),
		})
	}

	// Set up this container
	for _, e := range config.RuntimeConfig.PortMaps {
		useHostIP := false
		if e.HostIP != "" {
			hostIP := net.ParseIP(e.HostIP)
			isHostV6 := (hostIP.To4() == nil)
			// Ignore wrong-IP-family HostIPs
			if isV6 != isHostV6 {
				continue
			}

			// Unspecified addresses cannot be used as destination
			useHostIP = !hostIP.IsUnspecified()
		}

		if useHostIP {
			tx.Add(&nftables.Rule{
				Chain: hostIPHostPortsChain,
				Rule: nftables.Concat(
					"$IP daddr", e.HostIP,
					"$IP protocol", e.Protocol,
					"th dport", e.HostPort,
					"dnat $IP addr . port to", containerNet.IP, ".", e.ContainerPort,
				),
				Comment: &config.ContainerID,
			})
		} else {
			tx.Add(&nftables.Rule{
				Chain: hostPortsChain,
				Rule: nftables.Concat(
					"$IP protocol", e.Protocol,
					"th dport", e.HostPort,
					"dnat $IP addr . port to", containerNet.IP, ".", e.ContainerPort,
				),
				Comment: &config.ContainerID,
			})
		}
	}

	if *config.SNAT {
		// Add mark-to-masquerade rules for hairpin and localhost
		// In theory we should validate that the original dst IP and port are as
		// expected, but *any* traffic matching one of these patterns would need
		// to be masqueraded to be able to work correctly anyway.
		tx.Add(&nftables.Rule{
			Chain: masqueradingChain,
			Rule: nftables.Concat(
				"$IP saddr", containerNet.IP,
				"$IP daddr", containerNet.IP,
				"masquerade",
			),
			Comment: &config.ContainerID,
		})
		if !isV6 {
			tx.Add(&nftables.Rule{
				Chain: masqueradingChain,
				Rule: nftables.Concat(
					"$IP saddr 127.0.0.1",
					"$IP daddr", containerNet.IP,
					"masquerade",
				),
				Comment: &config.ContainerID,
			})
		}
	}

	err := nft.Run(context.TODO(), tx)
	if err != nil {
		return fmt.Errorf("unable to set up nftables rules for port mappings: %v", err)
	}

	return nil
}

func (pmNFT *portMapperNFTables) checkPorts(config *PortMapConf, containerNet net.IPNet) error {
	isV6 := (containerNet.IP.To4() == nil)

	var hostPorts, hostIPHostPorts, masqueradings int
	for _, e := range config.RuntimeConfig.PortMaps {
		if e.HostIP != "" {
			hostIPHostPorts++
		} else {
			hostPorts++
		}
	}
	if *config.SNAT {
		masqueradings = len(config.RuntimeConfig.PortMaps)
		if isV6 {
			masqueradings *= 2
		}
	}

	nft := pmNFT.getPortMapNFT(isV6)
	if hostPorts > 0 {
		err := checkPortsAgainstRules(nft, hostPortsChain, config.ContainerID, hostPorts)
		if err != nil {
			return err
		}
	}
	if hostIPHostPorts > 0 {
		err := checkPortsAgainstRules(nft, hostIPHostPortsChain, config.ContainerID, hostIPHostPorts)
		if err != nil {
			return err
		}
	}
	if masqueradings > 0 {
		err := checkPortsAgainstRules(nft, masqueradingChain, config.ContainerID, masqueradings)
		if err != nil {
			return err
		}
	}

	return nil
}

func checkPortsAgainstRules(nft nftables.Interface, chain, comment string, nPorts int) error {
	rules, err := nft.ListRules(context.TODO(), chain)
	if err != nil {
		return err
	}

	found := 0
	for _, r := range rules {
		if r.Comment != nil && *r.Comment == comment {
			found++
		}
	}
	if found < nPorts {
		return fmt.Errorf("missing hostport rules in %q chain", chain)
	}

	return nil
}

// unforwardPorts deletes any nftables rules created by this plugin.
// It should be idempotent - it will not error if the chain does not exist.
func (pmNFT *portMapperNFTables) unforwardPorts(config *PortMapConf) error {
	// Always clear both IPv4 and IPv6, just to be sure
	for _, family := range []nftables.Family{nftables.IPv4Family, nftables.IPv6Family} {
		nft := pmNFT.getPortMapNFT(family == nftables.IPv6Family)

		tx := nftables.NewTransaction()
		for _, chain := range []string{hostPortsChain, hostIPHostPortsChain, masqueradingChain} {
			rules, err := nft.ListRules(context.TODO(), chain)
			if err != nil {
				if nftables.IsNotFound(err) {
					continue
				}
				return fmt.Errorf("could not list rules in table %s: %w", tableName, err)
			}

			for _, r := range rules {
				if r.Comment != nil && *r.Comment == config.ContainerID {
					tx.Delete(r)
				}
			}
		}

		err := nft.Run(context.TODO(), tx)
		if err != nil {
			return fmt.Errorf("error deleting nftables rules: %w", err)
		}
	}

	return nil
}
