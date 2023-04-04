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
	"strings"
	"testing"

	"github.com/vishvananda/netlink"
	"sigs.k8s.io/knftables"
)

func Test_setupIPMasqNFTables(t *testing.T) {
	nft := knftables.NewFake(knftables.InetFamily, ipMasqTableName)

	containers := []struct {
		id   string
		addr string
	}{
		{
			id:   "one",
			addr: "192.168.1.1/24",
		},
		{
			id:   "two",
			addr: "192.168.1.2/24",
		},
		{
			id:   "three",
			addr: "192.168.99.5/24",
		},
	}

	for _, c := range containers {
		addr, err := netlink.ParseAddr(c.addr)
		if err != nil {
			t.Fatalf("failed to parse test addr: %v", err)
		}
		err = setupIPMasqNFTablesWithInterface(nft, addr.IPNet, "unit-test", c.id)
		if err != nil {
			t.Fatalf("error from setupIPMasqNFTables: %v", err)
		}
	}

	expected := strings.TrimSpace(`
add table inet cni_plugins_masquerade { comment "Masquerading for plugins from github.com/containernetworking/plugins" ; }
add chain inet cni_plugins_masquerade masq_checks { comment "Masquerade traffic from certain IPs to any (non-multicast) IP outside their subnet" ; }
add chain inet cni_plugins_masquerade postrouting { type nat hook postrouting priority 100 ; }
add rule inet cni_plugins_masquerade masq_checks ip saddr == 192.168.1.1 ip daddr != 192.168.1.0/24 masquerade comment "8c062ad391bb8ebf"
add rule inet cni_plugins_masquerade masq_checks ip saddr == 192.168.1.2 ip daddr != 192.168.1.0/24 masquerade comment "a777505f2d11fd66"
add rule inet cni_plugins_masquerade masq_checks ip saddr == 192.168.99.5 ip daddr != 192.168.99.0/24 masquerade comment "dab3c041fbc51d09"
add rule inet cni_plugins_masquerade postrouting ip daddr == 224.0.0.0/4  return
add rule inet cni_plugins_masquerade postrouting ip6 daddr == ff00::/8  return
add rule inet cni_plugins_masquerade postrouting goto masq_checks
`)
	dump := strings.TrimSpace(nft.Dump())
	if dump != expected {
		t.Errorf("expected nftables state:\n%s\n\nactual:\n%s\n\n", expected, dump)
	}

	// Add a new container reusing "one"'s address, before deleting "one"
	addr, err := netlink.ParseAddr(containers[0].addr)
	if err != nil {
		t.Fatalf("failed to parse test addr: %v", err)
	}
	err = setupIPMasqNFTablesWithInterface(nft, addr.IPNet, "unit-test", "four")
	if err != nil {
		t.Fatalf("error from setupIPMasqNFTables: %v", err)
	}

	// Now remove the original containers
	for _, c := range containers {
		addr, err := netlink.ParseAddr(c.addr)
		if err != nil {
			t.Fatalf("failed to parse test addr: %v", err)
		}
		err = teardownIPMasqNFTablesWithInterface(nft, addr.IPNet, "unit-test", c.id)
		if err != nil {
			t.Fatalf("error from teardownIPMasqNFTables: %v", err)
		}
	}

	// We should be left with just the rule for "four"

	expected = strings.TrimSpace(`
add table inet cni_plugins_masquerade { comment "Masquerading for plugins from github.com/containernetworking/plugins" ; }
add chain inet cni_plugins_masquerade masq_checks { comment "Masquerade traffic from certain IPs to any (non-multicast) IP outside their subnet" ; }
add chain inet cni_plugins_masquerade postrouting { type nat hook postrouting priority 100 ; }
add rule inet cni_plugins_masquerade masq_checks ip saddr == 192.168.1.1 ip daddr != 192.168.1.0/24 masquerade comment "a154bc98ffb3110e"
add rule inet cni_plugins_masquerade postrouting ip daddr == 224.0.0.0/4  return
add rule inet cni_plugins_masquerade postrouting ip6 daddr == ff00::/8  return
add rule inet cni_plugins_masquerade postrouting goto masq_checks
`)
	dump = strings.TrimSpace(nft.Dump())
	if dump != expected {
		t.Errorf("expected nftables state:\n%s\n\nactual:\n%s\n\n", expected, dump)
	}
}
