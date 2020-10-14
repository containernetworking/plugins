// Copyright 2018 CNI authors
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
	"github.com/containernetworking/cni/pkg/types/current"
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/vishvananda/netns"
	"strings"
)

// nftBackend implements the FirewallBackend interface
var _ FirewallBackend = &nftBackend{}

type nftBackend struct {
	ns               netns.NsHandle
	conn             *nftables.Conn
	tables           []*nftables.Table
	chains           []*nftables.Chain
	targetTable      string
	targetChain      string
	targetInterfaces map[string]*nftTargetInterface
}

type nftTargetInterface struct {
	addrs []*nftTargetInterfaceAddress
}

type nftTargetInterfaceAddress struct {
	conf  *current.IPConfig
	table *nftables.Table
	chain *nftables.Chain
}

func newNftablesBackend(conf *FirewallNetConf) (FirewallBackend, error) {
	backend := &nftBackend{
		targetTable: "filter",
		targetChain: "FORWARD",
		tables:      []*nftables.Table{},
		chains:      []*nftables.Chain{},
	}

	return backend, nil
}

func (nb *nftBackend) getChainName(intf string) string {
	name := "cni" + nb.ns.UniqueId() + intf
	name = strings.ReplaceAll(name, "(", "-")
	name = strings.ReplaceAll(name, ")", "-")
	name = strings.ReplaceAll(name, ":", "-")
	return strings.ToLower(name)
}

func (nb *nftBackend) initConn() error {
	if nb.conn != nil {
		return nil
	}
	ns, err := netns.Get()
	if err != nil {
		return err
	}
	conn := &nftables.Conn{
		NetNS: int(ns),
	}

	tables, err := conn.ListTables()
	if err != nil {
		return err
	}

	for _, table := range tables {
		if table == nil {
			continue
		}
		//if table.Name != nb.targetTable {
		//	continue
		//}
		if table.Family != nftables.TableFamilyIPv4 && table.Family != nftables.TableFamilyIPv6 {
			continue
		}
		nb.tables = append(nb.tables, table)
	}

	if len(nb.tables) == 0 {
		return fmt.Errorf("nftables table %s not found", nb.targetTable)
	}

	chains, err := conn.ListChains()
	if err != nil {
		return err
	}

	for _, chain := range chains {
		if chain == nil {
			continue
		}
		//if chain.Name != nb.targetChain {
		//	continue
		//}
		//if chain.Table.Name != nb.targetTable {
		//	continue
		//}
		if chain.Table.Family != nftables.TableFamilyIPv4 && chain.Table.Family != nftables.TableFamilyIPv6 {
			continue
		}
		nb.chains = append(nb.chains, chain)
	}

	if len(nb.chains) == 0 {
		return fmt.Errorf("nftables chain %s not found in %s table", nb.targetChain, nb.targetTable)
	}

	nb.ns = ns
	nb.conn = conn
	return nil
}

func (nb *nftBackend) addFilterChains() error {
	if err := nb.initConn(); err != nil {
		return err
	}

	for intfName, targetInterface := range nb.targetInterfaces {
		for _, addr := range targetInterface.addrs {
			chainName := nb.getChainName(intfName)

			// Add a new chain
			// defaultDropPolicy := nftables.ChainPolicyDrop
			chain := nb.conn.AddChain(&nftables.Chain{
				Name:  chainName,
				Table: addr.table,
				//Type:     nftables.ChainTypeFilter,
				//Hooknum:  nftables.ChainHookForward,
				//Priority: nftables.ChainPriorityFilter,
				//Policy:   &defaultDropPolicy,
			})
			if err := nb.conn.Flush(); err != nil {
				return fmt.Errorf(
					"failed adding chain %s for address %v of interface %s",
					chainName, addr.conf, intfName,
				)
			}

			// Add rule for inbound traffic
			// nft add rule oifname "dummy0" ip daddr 192.168.100.100 ct state established,related counter packets 0 bytes 0 accept
			inboundInterfaceRule := &nftables.Rule{
				Table: addr.table,
				Chain: chain,
				Exprs: []expr.Any{},
			}

			// meta load oifname => reg 1
			// cmp eq reg 1 0x6d6d7564 0x00003079 0x00000000 0x00000000
			inboundInterfaceRule.Exprs = append(inboundInterfaceRule.Exprs, &expr.Meta{
				Key:      expr.MetaKeyOIFNAME,
				Register: 1,
			})
			inboundInterfaceRule.Exprs = append(inboundInterfaceRule.Exprs, &expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     getNftInterfaceName(intfName),
			})

			if addr.conf.Version == "6" {
				// payload load 4b @ network header + 16 => reg 1
				// cmp eq reg 1 0xc8c8a8c0
				inboundInterfaceRule.Exprs = append(inboundInterfaceRule.Exprs, &expr.Payload{
					DestRegister: 1,
					Base:         expr.PayloadBaseNetworkHeader,
					// Offset:       8,
					Offset: 24,
					Len:    16,
				})
				inboundInterfaceRule.Exprs = append(inboundInterfaceRule.Exprs, &expr.Cmp{
					Op:       expr.CmpOpEq,
					Register: 1,
					Data:     addr.conf.Address.IP.To16(),
				})
			} else {
				// payload load 4b @ network header + 16 => reg 1
				// cmp eq reg 1 0x6464a8c0 ]
				inboundInterfaceRule.Exprs = append(inboundInterfaceRule.Exprs, &expr.Payload{
					DestRegister: 1,
					Base:         expr.PayloadBaseNetworkHeader,
					Offset:       16,
					Len:          4,
				})
				inboundInterfaceRule.Exprs = append(inboundInterfaceRule.Exprs, &expr.Cmp{
					Op:       expr.CmpOpEq,
					Register: 1,
					Data:     addr.conf.Address.IP.To4(),
				})
			}

			// ct load state => reg 1 ]
			// bitwise reg 1 = (reg=1 & 0x00000006 ) ^ 0x00000000
			// cmp neq reg 1 0x00000000
			inboundInterfaceRule.Exprs = append(inboundInterfaceRule.Exprs, &expr.Ct{
				Register: 1,
				Key:      expr.CtKeySTATE,
			})
			inboundInterfaceRule.Exprs = append(inboundInterfaceRule.Exprs, &expr.Bitwise{
				SourceRegister: 1,
				DestRegister:   1,
				Xor:            []byte{0x0, 0x0, 0x0, 0x0},
				Mask:           []byte("\x06\x00\x00\x00"),
				Len:            4,
			})
			inboundInterfaceRule.Exprs = append(inboundInterfaceRule.Exprs, &expr.Cmp{
				Op:       expr.CmpOpNeq,
				Register: 1,
				Data:     []byte{0x0, 0x0, 0x0, 0x0},
			})

			// counter pkts 0 bytes 0
			inboundInterfaceRule.Exprs = append(inboundInterfaceRule.Exprs, &expr.Counter{})
			// immediate reg 0 accept
			inboundInterfaceRule.Exprs = append(inboundInterfaceRule.Exprs, &expr.Verdict{
				Kind: expr.VerdictAccept,
			})

			nb.conn.AddRule(inboundInterfaceRule)
			if err := nb.conn.Flush(); err != nil {
				return fmt.Errorf(
					"failed adding outbound traffic rule in table %s chain %s for address %v of interface %s",
					addr.table.Name, chainName, addr.conf, intfName,
				)
			}

			// Add rule for outbound traffic
			// nft add rule ... iifname X ip saddr 1.1.1.1 counter packets 0 bytes 0 accept
			outboundInterfaceRule := &nftables.Rule{
				Table: addr.table,
				Chain: chain,
				Exprs: []expr.Any{},
			}

			outboundInterfaceRule.Exprs = append(outboundInterfaceRule.Exprs, &expr.Meta{
				Key:      expr.MetaKeyIIFNAME,
				Register: 1,
			})
			outboundInterfaceRule.Exprs = append(outboundInterfaceRule.Exprs, &expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     getNftInterfaceName(intfName),
			})

			if addr.conf.Version == "6" {
				outboundInterfaceRule.Exprs = append(outboundInterfaceRule.Exprs, &expr.Payload{
					DestRegister: 1,
					Base:         expr.PayloadBaseNetworkHeader,
					Offset:       8,
					// Offset: 24,
					Len: 16,
				})
				outboundInterfaceRule.Exprs = append(outboundInterfaceRule.Exprs, &expr.Cmp{
					Op:       expr.CmpOpEq,
					Register: 1,
					Data:     addr.conf.Address.IP.To16(),
				})
			} else {
				// payload load 4b @ network header + 12 => reg 1
				outboundInterfaceRule.Exprs = append(outboundInterfaceRule.Exprs, &expr.Payload{
					DestRegister: 1,
					Base:         expr.PayloadBaseNetworkHeader,
					Offset:       12,
					Len:          4,
				})
				// cmp eq reg 1 0x0245a8c0
				outboundInterfaceRule.Exprs = append(outboundInterfaceRule.Exprs, &expr.Cmp{
					Op:       expr.CmpOpEq,
					Register: 1,
					Data:     addr.conf.Address.IP.To4(),
				})
			}

			outboundInterfaceRule.Exprs = append(outboundInterfaceRule.Exprs, &expr.Counter{})
			outboundInterfaceRule.Exprs = append(outboundInterfaceRule.Exprs, &expr.Verdict{
				Kind: expr.VerdictAccept,
			})

			nb.conn.AddRule(outboundInterfaceRule)
			if err := nb.conn.Flush(); err != nil {
				return fmt.Errorf(
					"failed adding outbound traffic rule in table %s chain %s for address %v of interface %s",
					addr.table.Name, chainName, addr.conf, intfName,
				)
			}

			// Add intra interface rule
			// nft add rule iifname "dummy0" oifname "dummy0" counter packets 0 bytes 0 accept
			intraInterfaceRule := &nftables.Rule{
				Table: addr.table,
				Chain: chain,
				Exprs: []expr.Any{},
			}

			// meta load iifname => reg 1
			// cmp eq reg 1 0x6d6d7564 0x00003079 0x00000000 0x00000000
			intraInterfaceRule.Exprs = append(intraInterfaceRule.Exprs, &expr.Meta{
				Key:      expr.MetaKeyIIFNAME,
				Register: 1,
			})
			intraInterfaceRule.Exprs = append(intraInterfaceRule.Exprs, &expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     getNftInterfaceName(intfName),
			})

			// meta load oifname => reg 2
			// cmp eq reg 2 0x6d6d7564 0x00003079 0x00000000 0x00000000
			intraInterfaceRule.Exprs = append(intraInterfaceRule.Exprs, &expr.Meta{
				Key:      expr.MetaKeyOIFNAME,
				Register: 1,
			})
			intraInterfaceRule.Exprs = append(intraInterfaceRule.Exprs, &expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     getNftInterfaceName(intfName),
			})

			// counter pkts 0 bytes 0
			intraInterfaceRule.Exprs = append(intraInterfaceRule.Exprs, &expr.Counter{})
			// immediate reg 0 accept
			intraInterfaceRule.Exprs = append(intraInterfaceRule.Exprs, &expr.Verdict{
				Kind: expr.VerdictAccept,
			})

			nb.conn.AddRule(intraInterfaceRule)
			if err := nb.conn.Flush(); err != nil {
				return fmt.Errorf(
					"failed adding intra-interface rule in table %s chain %s for address %v of interface %s",
					addr.table.Name, chainName, addr.conf, intfName,
				)
			}

			// Finally, add the jump to the above chain in FORWARD chain.
			jumpRule := &nftables.Rule{
				Table: addr.table,
				Chain: addr.chain,
				Exprs: []expr.Any{},
			}
			jumpRule.Exprs = append(jumpRule.Exprs, &expr.Verdict{
				Kind:  expr.VerdictJump,
				Chain: chainName,
			})

			nb.conn.AddRule(jumpRule)
			if err := nb.conn.Flush(); err != nil {
				return fmt.Errorf(
					"failed adding jump rule in table %s chain %s for address %v of interface %s",
					addr.table.Name, addr.chain.Name, addr.conf, intfName,
				)
			}

		}
	}

	return nil
}

func (nb *nftBackend) validateFilters() error {
	if err := nb.initConn(); err != nil {
		return err
	}

	// Check whether there is a filter table for IP address
	// family used in IP configuration.
	for intfName, targetInteface := range nb.targetInterfaces {
		for _, addr := range targetInteface.addrs {
			tableFound := false
			chainFound := false
			for _, table := range nb.tables {
				if addr.conf.Version == "4" && table.Family != nftables.TableFamilyIPv4 {
					continue
				}
				if addr.conf.Version == "6" && table.Family != nftables.TableFamilyIPv6 {
					continue
				}
				tableFound = true
				addr.table = table
			}
			if !tableFound {
				return fmt.Errorf(
					"failed to find %s table for interface %s with config %v",
					nb.targetTable, intfName, addr.conf,
				)
			}
			for _, chain := range nb.chains {
				if addr.conf.Version == "4" && chain.Table.Family != nftables.TableFamilyIPv4 {
					continue
				}
				if addr.conf.Version == "6" && chain.Table.Family != nftables.TableFamilyIPv6 {
					continue
				}
				chainFound = true
				addr.chain = chain
			}
			if !chainFound {
				return fmt.Errorf(
					"failed to find %s chain for interface %s with config %v",
					nb.targetChain, intfName, addr.conf,
				)
			}
		}
	}
	return nil
}

func (nb *nftBackend) validateInput(result *current.Result) error {

	if len(result.Interfaces) == 0 {
		return fmt.Errorf("the data passed to firewall plugin did not contain network interfaces")
	}

	nb.targetInterfaces = make(map[string]*nftTargetInterface)

	intfMap := make(map[int]string)
	for i, intf := range result.Interfaces {
		if intf.Name == "" {
			return fmt.Errorf("the data passed to firewall plugin has no bridge name, e.g. cnibr0")
		}
		if _, interfaceExists := nb.targetInterfaces[intf.Name]; interfaceExists {
			return fmt.Errorf("found duplicate interface name %s", intf.Name)
		}
		targetInterface := &nftTargetInterface{
			addrs: []*nftTargetInterfaceAddress{},
		}
		nb.targetInterfaces[intf.Name] = targetInterface
		intfMap[i] = intf.Name
	}

	if len(result.IPs) == 0 {
		return fmt.Errorf("the data passed to firewall plugin has no IP addresses")
	}

	for _, addr := range result.IPs {
		if addr.Interface == nil {
			return fmt.Errorf("the ip config interface is nil: %v", addr)
		}
		if _, interfaceExists := intfMap[*addr.Interface]; !interfaceExists {
			return fmt.Errorf("the ip config points to non-existing interface: %v", addr)
		}
		intfName := intfMap[*addr.Interface]
		targetInterface := nb.targetInterfaces[intfName]
		targetInterfaceAddr := &nftTargetInterfaceAddress{
			conf: addr,
		}
		targetInterface.addrs = append(targetInterface.addrs, targetInterfaceAddr)
	}

	for intf, targetInterface := range nb.targetInterfaces {
		if targetInterface == nil {
			return fmt.Errorf("interface %s has no associated IP information", intf)
		}
		if len(targetInterface.addrs) == 0 {
			return fmt.Errorf("interface %s has no associated IP information", intf)
		}
	}

	for _, entry := range result.IPs {
		if entry.Address.String() == "" {
			return fmt.Errorf("the data passed to firewall plugin has empty IP address")
		}
	}

	return nil
}

func (nb *nftBackend) operate(op string, prevResult *current.Result) error {
	if err := nb.validateInput(prevResult); err != nil {
		return fmt.Errorf("failed input validation: %s", err)
	}
	if err := nb.validateFilters(); err != nil {
		return fmt.Errorf("failed parsing netfilter tables: %s", err)
	}

	if op == "add" {
		if err := nb.addFilterChains(); err != nil {
			return fmt.Errorf("failed adding netfilter chains: %s", err)
		}
		op = "check"
		nb.conn = nil
		if err := nb.initConn(); err != nil {
			return err
		}
	}

	for intfName, targetInterface := range nb.targetInterfaces {
		for _, addr := range targetInterface.addrs {
			chainName := nb.getChainName(intfName)
			var addrChain *nftables.Chain
			var forwardChain *nftables.Chain
			var forwardChainJumpRule *nftables.Rule

			for _, chain := range nb.chains {
				if chain.Name != chainName && chain.Name != nb.targetChain {
					continue
				}
				if addr.conf.Version == "4" && chain.Table.Family != nftables.TableFamilyIPv4 {
					continue
				}
				if addr.conf.Version == "6" && chain.Table.Family != nftables.TableFamilyIPv6 {
					continue
				}
				if chain.Name == chainName {
					addrChain = chain
					continue
				}
				forwardChain = chain
			}
			if forwardChain == nil {
				return fmt.Errorf("chain %s not found in %s table", nb.targetChain, addr.table.Name)
			}
			if addrChain == nil {
				return fmt.Errorf("chain %s not found in %s table", chainName, addr.table.Name)
			}

			forwardChainRules, err := nb.conn.GetRule(addr.table, forwardChain)
			if err != nil {
				return fmt.Errorf("failed getting rules from chain %s in %s table: %s", nb.targetChain, addr.table.Name, err)
			}
			if len(forwardChainRules) == 0 {
				return fmt.Errorf("no rules found in chain %s in %s table", nb.targetChain, addr.table.Name)
			}

			for _, r := range forwardChainRules {
				if len(r.Exprs) != 1 {
					continue
				}
				rr, err := r.Exprs[0].(*expr.Verdict)
				if err == false {
					continue
				}
				if rr.Kind != expr.VerdictJump {
					continue
				}
				if rr.Chain != chainName {
					continue
				}
				forwardChainJumpRule = r
				break
			}

			if op == "check" && forwardChainJumpRule == nil {
				return fmt.Errorf(
					"no jump rule to %s chain found in chain %s in %s table",
					chainName, nb.targetChain, addr.table.Name,
				)
			}

			if op == "delete" {
				nb.conn.DelRule(&nftables.Rule{
					Table:  &nftables.Table{Name: addr.table.Name, Family: addr.table.Family},
					Chain:  &nftables.Chain{Name: forwardChain.Name, Type: forwardChain.Type},
					Handle: forwardChainJumpRule.Handle,
				})

				if err := nb.conn.Flush(); err != nil {
					return fmt.Errorf(
						"error deleting jump rule to %s chain found in chain %s in %s table: %s",
						chainName, forwardChain.Name, addr.table.Name, err,
					)
				}

				nb.conn.DelChain(addrChain)
				if err := nb.conn.Flush(); err != nil {
					return fmt.Errorf(
						"error deleting %s chain in %s table: %s",
						chainName, addr.table.Name, err,
					)
				}

			}
		}
	}
	return nil
}

func (nb *nftBackend) Add(conf *FirewallNetConf, result *current.Result) error {
	if err := nb.operate("add", result); err != nil {
		return fmt.Errorf("nftBackend.Add() error: %s", err)
	}
	return nil
}

func (nb *nftBackend) Check(conf *FirewallNetConf, result *current.Result) error {
	if err := nb.operate("check", result); err != nil {
		return fmt.Errorf("nftBackend.Check() error: %s", err)
	}
	return nil
}

func (nb *nftBackend) Del(conf *FirewallNetConf, result *current.Result) error {
	if err := nb.operate("delete", result); err != nil {
		return fmt.Errorf("nftBackend.Del() error: %s", err)
	}
	return nil
}

func getNftInterfaceName(s string) []byte {
	b := make([]byte, 16)
	copy(b, []byte(s+"\x00"))
	return b
}
