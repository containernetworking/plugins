// Copyright 2017 CNI authors
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

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/containernetworking/cni/pkg/types"
)

var _ = Describe("portmapping configuration (iptables)", func() {
	netName := "testNetName"
	containerID := "icee6giejonei6sohng6ahngee7laquohquee9shiGo7fohferakah3Feiyoolu2pei7ciPhoh7shaoX6vai3vuf0ahfaeng8yohb9ceu0daez5hashee8ooYai5wa3y"

	for _, ver := range []string{"0.3.0", "0.3.1", "0.4.0", "1.0.0"} {
		// Redefine ver inside for scope so real value is picked up by each dynamically defined It()
		// See Gingkgo's "Patterns for dynamically generating tests" documentation.
		ver := ver

		Describe("Generating iptables chains", func() {
			Context("for DNAT", func() {
				It(fmt.Sprintf("[%s] generates a correct standard container chain", ver), func() {
					ch := genDnatChain(netName, containerID)

					Expect(ch).To(Equal(chain{
						table:       "nat",
						name:        "CNI-DN-bfd599665540dd91d5d28",
						entryChains: []string{TopLevelDNATChainName},
					}))
					configBytes := []byte(fmt.Sprintf(`{
						"name": "test",
						"type": "portmap",
						"cniVersion": "%s",
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
						"conditionsV4": ["-a", "b"],
						"conditionsV6": ["-c", "d"]
					}`, ver))

					conf, _, err := parseConfig(configBytes, "foo")
					Expect(err).NotTo(HaveOccurred())
					conf.ContainerID = containerID

					ch = genDnatChain(conf.Name, containerID)
					Expect(ch).To(Equal(chain{
						table:       "nat",
						name:        "CNI-DN-67e92b96e692a494b6b85",
						entryChains: []string{"CNI-HOSTPORT-DNAT"},
					}))

					n, err := types.ParseCIDR("10.0.0.2/24")
					Expect(err).NotTo(HaveOccurred())
					fillDnatRules(&ch, conf, *n)

					Expect(ch.entryRules).To(Equal([][]string{
						{
							"-m", "comment", "--comment",
							fmt.Sprintf("dnat name: \"test\" id: \"%s\"", containerID),
							"-m", "multiport",
							"-p", "tcp",
							"--destination-ports", "8080,8081,8083,8084,8085,8086",
							"-a", "b",
						},
						{
							"-m", "comment", "--comment",
							fmt.Sprintf("dnat name: \"test\" id: \"%s\"", containerID),
							"-m", "multiport",
							"-p", "udp",
							"--destination-ports", "8080,8082",
							"-a", "b",
						},
					}))

					Expect(ch.rules).To(Equal([][]string{
						// tcp rules and not hostIP
						{"-p", "tcp", "--dport", "8080", "-s", "10.0.0.2/24", "-j", "CNI-HOSTPORT-SETMARK"},
						{"-p", "tcp", "--dport", "8080", "-s", "127.0.0.1", "-j", "CNI-HOSTPORT-SETMARK"},
						{"-p", "tcp", "--dport", "8080", "-j", "DNAT", "--to-destination", "10.0.0.2:80"},
						{"-p", "tcp", "--dport", "8081", "-s", "10.0.0.2/24", "-j", "CNI-HOSTPORT-SETMARK"},
						{"-p", "tcp", "--dport", "8081", "-s", "127.0.0.1", "-j", "CNI-HOSTPORT-SETMARK"},
						{"-p", "tcp", "--dport", "8081", "-j", "DNAT", "--to-destination", "10.0.0.2:80"},
						// udp rules and not hostIP
						{"-p", "udp", "--dport", "8080", "-s", "10.0.0.2/24", "-j", "CNI-HOSTPORT-SETMARK"},
						{"-p", "udp", "--dport", "8080", "-s", "127.0.0.1", "-j", "CNI-HOSTPORT-SETMARK"},
						{"-p", "udp", "--dport", "8080", "-j", "DNAT", "--to-destination", "10.0.0.2:81"},
						{"-p", "udp", "--dport", "8082", "-s", "10.0.0.2/24", "-j", "CNI-HOSTPORT-SETMARK"},
						{"-p", "udp", "--dport", "8082", "-s", "127.0.0.1", "-j", "CNI-HOSTPORT-SETMARK"},
						{"-p", "udp", "--dport", "8082", "-j", "DNAT", "--to-destination", "10.0.0.2:82"},
						// tcp rules and hostIP
						{"-p", "tcp", "--dport", "8083", "-d", "192.168.0.2", "-s", "10.0.0.2/24", "-j", "CNI-HOSTPORT-SETMARK"},
						{"-p", "tcp", "--dport", "8083", "-d", "192.168.0.2", "-s", "127.0.0.1", "-j", "CNI-HOSTPORT-SETMARK"},
						{"-p", "tcp", "--dport", "8083", "-d", "192.168.0.2", "-j", "DNAT", "--to-destination", "10.0.0.2:83"},
						// tcp rules and hostIP = "0.0.0.0"
						{"-p", "tcp", "--dport", "8084", "-s", "10.0.0.2/24", "-j", "CNI-HOSTPORT-SETMARK"},
						{"-p", "tcp", "--dport", "8084", "-s", "127.0.0.1", "-j", "CNI-HOSTPORT-SETMARK"},
						{"-p", "tcp", "--dport", "8084", "-j", "DNAT", "--to-destination", "10.0.0.2:84"},
					}))

					ch.rules = nil
					ch.entryRules = nil

					n, err = types.ParseCIDR("2001:db8::2/64")
					Expect(err).NotTo(HaveOccurred())
					fillDnatRules(&ch, conf, *n)

					Expect(ch.rules).To(Equal([][]string{
						// tcp rules and not hostIP
						{"-p", "tcp", "--dport", "8080", "-s", "2001:db8::2/64", "-j", "CNI-HOSTPORT-SETMARK"},
						{"-p", "tcp", "--dport", "8080", "-j", "DNAT", "--to-destination", "[2001:db8::2]:80"},
						{"-p", "tcp", "--dport", "8081", "-s", "2001:db8::2/64", "-j", "CNI-HOSTPORT-SETMARK"},
						{"-p", "tcp", "--dport", "8081", "-j", "DNAT", "--to-destination", "[2001:db8::2]:80"},
						// udp rules and not hostIP
						{"-p", "udp", "--dport", "8080", "-s", "2001:db8::2/64", "-j", "CNI-HOSTPORT-SETMARK"},
						{"-p", "udp", "--dport", "8080", "-j", "DNAT", "--to-destination", "[2001:db8::2]:81"},
						{"-p", "udp", "--dport", "8082", "-s", "2001:db8::2/64", "-j", "CNI-HOSTPORT-SETMARK"},
						{"-p", "udp", "--dport", "8082", "-j", "DNAT", "--to-destination", "[2001:db8::2]:82"},
						// tcp rules and hostIP
						{"-p", "tcp", "--dport", "8085", "-d", "2001:db8:a::1", "-s", "2001:db8::2/64", "-j", "CNI-HOSTPORT-SETMARK"},
						{"-p", "tcp", "--dport", "8085", "-d", "2001:db8:a::1", "-j", "DNAT", "--to-destination", "[2001:db8::2]:85"},
						// tcp rules and hostIP = "::"
						{"-p", "tcp", "--dport", "8086", "-s", "2001:db8::2/64", "-j", "CNI-HOSTPORT-SETMARK"},
						{"-p", "tcp", "--dport", "8086", "-j", "DNAT", "--to-destination", "[2001:db8::2]:86"},
					}))

					// Disable snat, generate rules
					ch.rules = nil
					ch.entryRules = nil
					fvar := false
					conf.SNAT = &fvar

					n, err = types.ParseCIDR("10.0.0.2/24")
					Expect(err).NotTo(HaveOccurred())
					fillDnatRules(&ch, conf, *n)
					Expect(ch.rules).To(Equal([][]string{
						{"-p", "tcp", "--dport", "8080", "-j", "DNAT", "--to-destination", "10.0.0.2:80"},
						{"-p", "tcp", "--dport", "8081", "-j", "DNAT", "--to-destination", "10.0.0.2:80"},
						{"-p", "udp", "--dport", "8080", "-j", "DNAT", "--to-destination", "10.0.0.2:81"},
						{"-p", "udp", "--dport", "8082", "-j", "DNAT", "--to-destination", "10.0.0.2:82"},
						{"-p", "tcp", "--dport", "8083", "-d", "192.168.0.2", "-j", "DNAT", "--to-destination", "10.0.0.2:83"},
						{"-p", "tcp", "--dport", "8084", "-j", "DNAT", "--to-destination", "10.0.0.2:84"},
					}))
				})

				It(fmt.Sprintf("[%s] generates a correct chain with external mark", ver), func() {
					ch := genDnatChain(netName, containerID)

					Expect(ch).To(Equal(chain{
						table:       "nat",
						name:        "CNI-DN-bfd599665540dd91d5d28",
						entryChains: []string{TopLevelDNATChainName},
					}))
					configBytes := []byte(fmt.Sprintf(`{
						"name": "test",
						"type": "portmap",
						"cniVersion": "%s",
						"runtimeConfig": {
							"portMappings": [
								{ "hostPort": 8080, "containerPort": 80, "protocol": "tcp"}
							]
						},
						"externalSetMarkChain": "PLZ-SET-MARK",
						"conditionsV4": ["-a", "b"],
						"conditionsV6": ["-c", "d"]
					}`, ver))

					conf, _, err := parseConfig(configBytes, "foo")
					Expect(err).NotTo(HaveOccurred())
					conf.ContainerID = containerID

					ch = genDnatChain(conf.Name, containerID)
					n, err := types.ParseCIDR("10.0.0.2/24")
					Expect(err).NotTo(HaveOccurred())
					fillDnatRules(&ch, conf, *n)
					Expect(ch.rules).To(Equal([][]string{
						{"-p", "tcp", "--dport", "8080", "-s", "10.0.0.2/24", "-j", "PLZ-SET-MARK"},
						{"-p", "tcp", "--dport", "8080", "-s", "127.0.0.1", "-j", "PLZ-SET-MARK"},
						{"-p", "tcp", "--dport", "8080", "-j", "DNAT", "--to-destination", "10.0.0.2:80"},
					}))
				})

				It(fmt.Sprintf("[%s] generates a correct top-level chain", ver), func() {
					ch := genToplevelDnatChain()

					Expect(ch).To(Equal(chain{
						table:       "nat",
						name:        "CNI-HOSTPORT-DNAT",
						entryChains: []string{"PREROUTING", "OUTPUT"},
						entryRules:  [][]string{{"-m", "addrtype", "--dst-type", "LOCAL"}},
					}))
				})

				It(fmt.Sprintf("[%s] generates the correct mark chains", ver), func() {
					masqBit := 5
					ch := genSetMarkChain(masqBit)
					Expect(ch).To(Equal(chain{
						table: "nat",
						name:  "CNI-HOSTPORT-SETMARK",
						rules: [][]string{{
							"-m", "comment",
							"--comment", "CNI portfwd masquerade mark",
							"-j", "MARK",
							"--set-xmark", "0x20/0x20",
						}},
					}))

					ch = genMarkMasqChain(masqBit)
					Expect(ch).To(Equal(chain{
						table:       "nat",
						name:        "CNI-HOSTPORT-MASQ",
						entryChains: []string{"POSTROUTING"},
						entryRules: [][]string{{
							"-m", "comment",
							"--comment", "CNI portfwd requiring masquerade",
						}},
						rules: [][]string{{
							"-m", "mark",
							"--mark", "0x20/0x20",
							"-j", "MASQUERADE",
						}},
						prependEntry: true,
					}))
				})
			})
		})
	}
})
