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
	"fmt"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"sigs.k8s.io/knftables"

	"github.com/containernetworking/cni/pkg/types"
)

var _ = Describe("portmapping configuration (nftables)", func() {
	containerID := "icee6giejonei6so"

	for _, ver := range []string{"0.3.0", "0.3.1", "0.4.0", "1.0.0"} {
		// Redefine ver inside for scope so real value is picked up by each dynamically defined It()
		// See Gingkgo's "Patterns for dynamically generating tests" documentation.
		ver := ver

		Describe("nftables rules", func() {
			var pmNFT *portMapperNFTables
			var ipv4Fake, ipv6Fake *knftables.Fake
			BeforeEach(func() {
				ipv4Fake = knftables.NewFake(knftables.IPv4Family, tableName)
				ipv6Fake = knftables.NewFake(knftables.IPv6Family, tableName)
				pmNFT = &portMapperNFTables{
					ipv4: ipv4Fake,
					ipv6: ipv6Fake,
				}
			})

			It(fmt.Sprintf("[%s] generates correct rules on ADD", ver), func() {
				configBytes := []byte(fmt.Sprintf(`{
					"name": "test",
					"type": "portmap",
					"cniVersion": "%s",
					"backend": "nftables",
					"runtimeConfig": {
						"portMappings": [
							{ "hostPort": 8080, "containerPort": 80, "protocol": "tcp"},
							{ "hostPort": 8081, "containerPort": 80, "protocol": "tcp"},
							{ "hostPort": 8080, "containerPort": 81, "protocol": "udp"},
							{ "hostPort": 8082, "containerPort": 82, "protocol": "udp"},
							{ "hostPort": 8083, "containerPort": 83, "protocol": "tcp", "hostIP": "192.168.0.2"},
							{ "hostPort": 8084, "containerPort": 84, "protocol": "tcp", "hostIP": "0.0.0.0"},
							{ "hostPort": 8085, "containerPort": 85, "protocol": "tcp", "hostIP": "2001:db8:a::1"},
							{ "hostPort": 8086, "containerPort": 86, "protocol": "tcp", "hostIP": "::"}
						]
					},
					"snat": true,
					"conditionsV4": ["a", "b"],
					"conditionsV6": ["c", "d"]
				}`, ver))

				conf, _, err := parseConfig(configBytes, "foo")
				Expect(err).NotTo(HaveOccurred())
				conf.ContainerID = containerID

				containerNet, err := types.ParseCIDR("10.0.0.2/24")
				Expect(err).NotTo(HaveOccurred())

				err = pmNFT.forwardPorts(conf, *containerNet)
				Expect(err).NotTo(HaveOccurred())

				expectedRules := strings.TrimSpace(`
add table ip cni_hostport { comment "CNI portmap plugin" ; }
add chain ip cni_hostport hostip_hostports
add chain ip cni_hostport hostports
add chain ip cni_hostport masquerading { type nat hook postrouting priority 100 ; }
add chain ip cni_hostport output { type nat hook output priority -100 ; }
add chain ip cni_hostport prerouting { type nat hook prerouting priority -100 ; }
add rule ip cni_hostport hostip_hostports ip daddr 192.168.0.2 tcp dport 8083 dnat to 10.0.0.2:83 comment "icee6giejonei6so"
add rule ip cni_hostport hostports tcp dport 8080 dnat to 10.0.0.2:80 comment "icee6giejonei6so"
add rule ip cni_hostport hostports tcp dport 8081 dnat to 10.0.0.2:80 comment "icee6giejonei6so"
add rule ip cni_hostport hostports udp dport 8080 dnat to 10.0.0.2:81 comment "icee6giejonei6so"
add rule ip cni_hostport hostports udp dport 8082 dnat to 10.0.0.2:82 comment "icee6giejonei6so"
add rule ip cni_hostport hostports tcp dport 8084 dnat to 10.0.0.2:84 comment "icee6giejonei6so"
add rule ip cni_hostport masquerading ip saddr 10.0.0.2 ip daddr 10.0.0.2 masquerade comment "icee6giejonei6so"
add rule ip cni_hostport masquerading ip saddr 127.0.0.1 ip daddr 10.0.0.2 masquerade comment "icee6giejonei6so"
add rule ip cni_hostport output a b jump hostip_hostports
add rule ip cni_hostport output a b fib daddr type local jump hostports
add rule ip cni_hostport prerouting a b jump hostip_hostports
add rule ip cni_hostport prerouting a b jump hostports
`)
				actualRules := strings.TrimSpace(ipv4Fake.Dump())
				Expect(actualRules).To(Equal(expectedRules))

				// Disable snat, generate IPv6 rules
				*conf.SNAT = false
				containerNet, err = types.ParseCIDR("2001:db8::2/64")
				Expect(err).NotTo(HaveOccurred())

				err = pmNFT.forwardPorts(conf, *containerNet)
				Expect(err).NotTo(HaveOccurred())

				expectedRules = strings.TrimSpace(`
add table ip6 cni_hostport { comment "CNI portmap plugin" ; }
add chain ip6 cni_hostport hostip_hostports
add chain ip6 cni_hostport hostports
add chain ip6 cni_hostport output { type nat hook output priority -100 ; }
add chain ip6 cni_hostport prerouting { type nat hook prerouting priority -100 ; }
add rule ip6 cni_hostport hostip_hostports ip6 daddr 2001:db8:a::1 tcp dport 8085 dnat to [2001:db8::2]:85 comment "icee6giejonei6so"
add rule ip6 cni_hostport hostports tcp dport 8080 dnat to [2001:db8::2]:80 comment "icee6giejonei6so"
add rule ip6 cni_hostport hostports tcp dport 8081 dnat to [2001:db8::2]:80 comment "icee6giejonei6so"
add rule ip6 cni_hostport hostports udp dport 8080 dnat to [2001:db8::2]:81 comment "icee6giejonei6so"
add rule ip6 cni_hostport hostports udp dport 8082 dnat to [2001:db8::2]:82 comment "icee6giejonei6so"
add rule ip6 cni_hostport hostports tcp dport 8086 dnat to [2001:db8::2]:86 comment "icee6giejonei6so"
add rule ip6 cni_hostport output c d jump hostip_hostports
add rule ip6 cni_hostport output c d fib daddr type local jump hostports
add rule ip6 cni_hostport prerouting c d jump hostip_hostports
add rule ip6 cni_hostport prerouting c d jump hostports
`)
				actualRules = strings.TrimSpace(ipv6Fake.Dump())
				Expect(actualRules).To(Equal(expectedRules))
			})
		})
	}
})
