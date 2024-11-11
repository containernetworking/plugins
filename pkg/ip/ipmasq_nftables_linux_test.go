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

package ip

import (
	"net"
	"strings"
	"testing"

	"github.com/vishvananda/netlink"
	"sigs.k8s.io/knftables"

	"github.com/containernetworking/cni/pkg/types"
)

func Test_setupIPMasqNFTables(t *testing.T) {
	nft := knftables.NewFake(knftables.InetFamily, ipMasqTableName)

	containers := []struct {
		network     string
		ifname      string
		containerID string
		addrs       []string
	}{
		{
			network:     "unit-test",
			ifname:      "eth0",
			containerID: "one",
			addrs:       []string{"192.168.1.1/24"},
		},
		{
			network:     "unit-test",
			ifname:      "eth0",
			containerID: "two",
			addrs:       []string{"192.168.1.2/24", "2001:db8::2/64"},
		},
		{
			network:     "unit-test",
			ifname:      "eth0",
			containerID: "three",
			addrs:       []string{"192.168.99.5/24"},
		},
		{
			network:     "alternate",
			ifname:      "net1",
			containerID: "three",
			addrs: []string{
				"10.0.0.5/24",
				"10.0.0.6/24",
				"10.0.1.7/24",
				"2001:db8::5/64",
				"2001:db8::6/64",
				"2001:db8:1::7/64",
			},
		},
	}

	for _, c := range containers {
		ipns := []*net.IPNet{}
		for _, addr := range c.addrs {
			nladdr, err := netlink.ParseAddr(addr)
			if err != nil {
				t.Fatalf("failed to parse test addr: %v", err)
			}
			ipns = append(ipns, nladdr.IPNet)
		}
		err := setupIPMasqNFTablesWithInterface(nft, ipns, c.network, c.ifname, c.containerID)
		if err != nil {
			t.Fatalf("error from setupIPMasqNFTables: %v", err)
		}

	}

	expected := strings.TrimSpace(`
add table inet cni_plugins_masquerade { comment "Masquerading for plugins from github.com/containernetworking/plugins" ; }
add chain inet cni_plugins_masquerade masq_checks { comment "Masquerade traffic from certain IPs to any (non-multicast) IP outside their subnet" ; }
add chain inet cni_plugins_masquerade postrouting { type nat hook postrouting priority 100 ; }
add rule inet cni_plugins_masquerade masq_checks ip saddr == 192.168.1.1 ip daddr != 192.168.1.0/24 masquerade comment "6fd94d501e58f0aa-287fc69eff0574a2, net: unit-test, if: eth0, id: one"
add rule inet cni_plugins_masquerade masq_checks ip saddr == 192.168.1.2 ip daddr != 192.168.1.0/24 masquerade comment "6fd94d501e58f0aa-d750b2c8f0f25d5f, net: unit-test, if: eth0, id: two"
add rule inet cni_plugins_masquerade masq_checks ip6 saddr == 2001:db8::2 ip6 daddr != 2001:db8::/64 masquerade comment "6fd94d501e58f0aa-d750b2c8f0f25d5f, net: unit-test, if: eth0, id: two"
add rule inet cni_plugins_masquerade masq_checks ip saddr == 192.168.99.5 ip daddr != 192.168.99.0/24 masquerade comment "6fd94d501e58f0aa-a4d4adb82b669cfe, net: unit-test, if: eth0, id: three"
add rule inet cni_plugins_masquerade masq_checks ip saddr == 10.0.0.5 ip daddr != 10.0.0.0/24 masquerade comment "82783ef24bdc7036-acb19d111858e348, net: alternate, if: net1, id: three"
add rule inet cni_plugins_masquerade masq_checks ip saddr == 10.0.0.6 ip daddr != 10.0.0.0/24 masquerade comment "82783ef24bdc7036-acb19d111858e348, net: alternate, if: net1, id: three"
add rule inet cni_plugins_masquerade masq_checks ip saddr == 10.0.1.7 ip daddr != 10.0.1.0/24 masquerade comment "82783ef24bdc7036-acb19d111858e348, net: alternate, if: net1, id: three"
add rule inet cni_plugins_masquerade masq_checks ip6 saddr == 2001:db8::5 ip6 daddr != 2001:db8::/64 masquerade comment "82783ef24bdc7036-acb19d111858e348, net: alternate, if: net1, id: three"
add rule inet cni_plugins_masquerade masq_checks ip6 saddr == 2001:db8::6 ip6 daddr != 2001:db8::/64 masquerade comment "82783ef24bdc7036-acb19d111858e348, net: alternate, if: net1, id: three"
add rule inet cni_plugins_masquerade masq_checks ip6 saddr == 2001:db8:1::7 ip6 daddr != 2001:db8:1::/64 masquerade comment "82783ef24bdc7036-acb19d111858e348, net: alternate, if: net1, id: three"
add rule inet cni_plugins_masquerade postrouting ip daddr == 224.0.0.0/4  return
add rule inet cni_plugins_masquerade postrouting ip6 daddr == ff00::/8  return
add rule inet cni_plugins_masquerade postrouting goto masq_checks
`)
	dump := strings.TrimSpace(nft.Dump())
	if dump != expected {
		t.Errorf("expected nftables state:\n%s\n\nactual:\n%s\n\n", expected, dump)
	}

	// Add a new container reusing "one"'s address, before deleting "one"
	c := containers[0]
	addr, err := netlink.ParseAddr(c.addrs[0])
	if err != nil {
		t.Fatalf("failed to parse test addr: %v", err)
	}
	err = setupIPMasqNFTablesWithInterface(nft, []*net.IPNet{addr.IPNet}, "unit-test", "eth0", "four")
	if err != nil {
		t.Fatalf("error from setupIPMasqNFTables: %v", err)
	}

	// Remove "one"
	err = teardownIPMasqNFTablesWithInterface(nft, []*net.IPNet{addr.IPNet}, c.network, c.ifname, c.containerID)
	if err != nil {
		t.Fatalf("error from teardownIPMasqNFTables: %v", err)
	}

	// Check that "one" was deleted (and "four" wasn't)
	expected = strings.TrimSpace(`
add table inet cni_plugins_masquerade { comment "Masquerading for plugins from github.com/containernetworking/plugins" ; }
add chain inet cni_plugins_masquerade masq_checks { comment "Masquerade traffic from certain IPs to any (non-multicast) IP outside their subnet" ; }
add chain inet cni_plugins_masquerade postrouting { type nat hook postrouting priority 100 ; }
add rule inet cni_plugins_masquerade masq_checks ip saddr == 192.168.1.2 ip daddr != 192.168.1.0/24 masquerade comment "6fd94d501e58f0aa-d750b2c8f0f25d5f, net: unit-test, if: eth0, id: two"
add rule inet cni_plugins_masquerade masq_checks ip6 saddr == 2001:db8::2 ip6 daddr != 2001:db8::/64 masquerade comment "6fd94d501e58f0aa-d750b2c8f0f25d5f, net: unit-test, if: eth0, id: two"
add rule inet cni_plugins_masquerade masq_checks ip saddr == 192.168.99.5 ip daddr != 192.168.99.0/24 masquerade comment "6fd94d501e58f0aa-a4d4adb82b669cfe, net: unit-test, if: eth0, id: three"
add rule inet cni_plugins_masquerade masq_checks ip saddr == 10.0.0.5 ip daddr != 10.0.0.0/24 masquerade comment "82783ef24bdc7036-acb19d111858e348, net: alternate, if: net1, id: three"
add rule inet cni_plugins_masquerade masq_checks ip saddr == 10.0.0.6 ip daddr != 10.0.0.0/24 masquerade comment "82783ef24bdc7036-acb19d111858e348, net: alternate, if: net1, id: three"
add rule inet cni_plugins_masquerade masq_checks ip saddr == 10.0.1.7 ip daddr != 10.0.1.0/24 masquerade comment "82783ef24bdc7036-acb19d111858e348, net: alternate, if: net1, id: three"
add rule inet cni_plugins_masquerade masq_checks ip6 saddr == 2001:db8::5 ip6 daddr != 2001:db8::/64 masquerade comment "82783ef24bdc7036-acb19d111858e348, net: alternate, if: net1, id: three"
add rule inet cni_plugins_masquerade masq_checks ip6 saddr == 2001:db8::6 ip6 daddr != 2001:db8::/64 masquerade comment "82783ef24bdc7036-acb19d111858e348, net: alternate, if: net1, id: three"
add rule inet cni_plugins_masquerade masq_checks ip6 saddr == 2001:db8:1::7 ip6 daddr != 2001:db8:1::/64 masquerade comment "82783ef24bdc7036-acb19d111858e348, net: alternate, if: net1, id: three"
add rule inet cni_plugins_masquerade masq_checks ip saddr == 192.168.1.1 ip daddr != 192.168.1.0/24 masquerade comment "6fd94d501e58f0aa-e766de567ef6c543, net: unit-test, if: eth0, id: four"
add rule inet cni_plugins_masquerade postrouting ip daddr == 224.0.0.0/4  return
add rule inet cni_plugins_masquerade postrouting ip6 daddr == ff00::/8  return
add rule inet cni_plugins_masquerade postrouting goto masq_checks
`)
	dump = strings.TrimSpace(nft.Dump())
	if dump != expected {
		t.Errorf("expected nftables state:\n%s\n\nactual:\n%s\n\n", expected, dump)
	}

	// GC "four" from the "unit-test" network
	err = gcIPMasqNFTablesWithInterface(nft, "unit-test", []types.GCAttachment{
		{IfName: "eth0", ContainerID: "two"},
		{IfName: "eth0", ContainerID: "three"},
		// (irrelevant extra element)
		{IfName: "eth0", ContainerID: "one"},
	})
	if err != nil {
		t.Fatalf("error from gcIPMasqNFTables: %v", err)
	}
	// GC the "alternate" network without removing anything
	err = gcIPMasqNFTablesWithInterface(nft, "alternate", []types.GCAttachment{
		{IfName: "net1", ContainerID: "three"},
	})
	if err != nil {
		t.Fatalf("error from gcIPMasqNFTables: %v", err)
	}

	// Re-dump
	expected = strings.TrimSpace(`
add table inet cni_plugins_masquerade { comment "Masquerading for plugins from github.com/containernetworking/plugins" ; }
add chain inet cni_plugins_masquerade masq_checks { comment "Masquerade traffic from certain IPs to any (non-multicast) IP outside their subnet" ; }
add chain inet cni_plugins_masquerade postrouting { type nat hook postrouting priority 100 ; }
add rule inet cni_plugins_masquerade masq_checks ip saddr == 192.168.1.2 ip daddr != 192.168.1.0/24 masquerade comment "6fd94d501e58f0aa-d750b2c8f0f25d5f, net: unit-test, if: eth0, id: two"
add rule inet cni_plugins_masquerade masq_checks ip6 saddr == 2001:db8::2 ip6 daddr != 2001:db8::/64 masquerade comment "6fd94d501e58f0aa-d750b2c8f0f25d5f, net: unit-test, if: eth0, id: two"
add rule inet cni_plugins_masquerade masq_checks ip saddr == 192.168.99.5 ip daddr != 192.168.99.0/24 masquerade comment "6fd94d501e58f0aa-a4d4adb82b669cfe, net: unit-test, if: eth0, id: three"
add rule inet cni_plugins_masquerade masq_checks ip saddr == 10.0.0.5 ip daddr != 10.0.0.0/24 masquerade comment "82783ef24bdc7036-acb19d111858e348, net: alternate, if: net1, id: three"
add rule inet cni_plugins_masquerade masq_checks ip saddr == 10.0.0.6 ip daddr != 10.0.0.0/24 masquerade comment "82783ef24bdc7036-acb19d111858e348, net: alternate, if: net1, id: three"
add rule inet cni_plugins_masquerade masq_checks ip saddr == 10.0.1.7 ip daddr != 10.0.1.0/24 masquerade comment "82783ef24bdc7036-acb19d111858e348, net: alternate, if: net1, id: three"
add rule inet cni_plugins_masquerade masq_checks ip6 saddr == 2001:db8::5 ip6 daddr != 2001:db8::/64 masquerade comment "82783ef24bdc7036-acb19d111858e348, net: alternate, if: net1, id: three"
add rule inet cni_plugins_masquerade masq_checks ip6 saddr == 2001:db8::6 ip6 daddr != 2001:db8::/64 masquerade comment "82783ef24bdc7036-acb19d111858e348, net: alternate, if: net1, id: three"
add rule inet cni_plugins_masquerade masq_checks ip6 saddr == 2001:db8:1::7 ip6 daddr != 2001:db8:1::/64 masquerade comment "82783ef24bdc7036-acb19d111858e348, net: alternate, if: net1, id: three"
add rule inet cni_plugins_masquerade postrouting ip daddr == 224.0.0.0/4  return
add rule inet cni_plugins_masquerade postrouting ip6 daddr == ff00::/8  return
add rule inet cni_plugins_masquerade postrouting goto masq_checks
`)
	dump = strings.TrimSpace(nft.Dump())
	if dump != expected {
		t.Errorf("expected nftables state:\n%s\n\nactual:\n%s\n\n", expected, dump)
	}

	// GC everything
	err = gcIPMasqNFTablesWithInterface(nft, "unit-test", []types.GCAttachment{})
	if err != nil {
		t.Fatalf("error from gcIPMasqNFTables: %v", err)
	}
	err = gcIPMasqNFTablesWithInterface(nft, "alternate", []types.GCAttachment{})
	if err != nil {
		t.Fatalf("error from gcIPMasqNFTables: %v", err)
	}

	expected = strings.TrimSpace(`
add table inet cni_plugins_masquerade { comment "Masquerading for plugins from github.com/containernetworking/plugins" ; }
add chain inet cni_plugins_masquerade masq_checks { comment "Masquerade traffic from certain IPs to any (non-multicast) IP outside their subnet" ; }
add chain inet cni_plugins_masquerade postrouting { type nat hook postrouting priority 100 ; }
add rule inet cni_plugins_masquerade postrouting ip daddr == 224.0.0.0/4  return
add rule inet cni_plugins_masquerade postrouting ip6 daddr == ff00::/8  return
add rule inet cni_plugins_masquerade postrouting goto masq_checks
`)
	dump = strings.TrimSpace(nft.Dump())
	if dump != expected {
		t.Errorf("expected nftables state:\n%s\n\nactual:\n%s\n\n", expected, dump)
	}
}
