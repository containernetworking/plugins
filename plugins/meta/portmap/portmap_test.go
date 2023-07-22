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

var _ = Describe("portmapping configuration", func() {
	for _, ver := range []string{"0.3.0", "0.3.1", "0.4.0", "1.0.0"} {
		// Redefine ver inside for scope so real value is picked up by each dynamically defined It()
		// See Gingkgo's "Patterns for dynamically generating tests" documentation.
		ver := ver

		Context("config parsing", func() {
			It(fmt.Sprintf("[%s] correctly parses an ADD config", ver), func() {
				configBytes := []byte(fmt.Sprintf(`{
					"name": "test",
					"type": "portmap",
					"cniVersion": "%s",
					"backend": "iptables",
					"runtimeConfig": {
						"portMappings": [
							{ "hostPort": 8080, "containerPort": 80, "protocol": "tcp"},
							{ "hostPort": 8081, "containerPort": 81, "protocol": "udp"}
						]
					},
					"snat": false,
					"conditionsV4": ["-a", "b"],
					"conditionsV6": ["-c", "d"],
					"prevResult": {
						"interfaces": [
							{"name": "host"},
							{"name": "container", "sandbox":"netns"}
						],
						"ips": [
							{
								"version": "4",
								"address": "10.0.0.1/24",
								"gateway": "10.0.0.1",
								"interface": 0
							},
							{
								"version": "6",
								"address": "2001:db8:1::2/64",
								"gateway": "2001:db8:1::1",
								"interface": 1
							},
							{
								"version": "4",
								"address": "10.0.0.2/24",
								"gateway": "10.0.0.1",
								"interface": 1
							}
						]
					}
				}`, ver))
				c, _, err := parseConfig(configBytes, "container")
				Expect(err).NotTo(HaveOccurred())
				Expect(c.CNIVersion).To(Equal(ver))
				Expect(c.ConditionsV4).To(Equal(&[]string{"-a", "b"}))
				Expect(c.ConditionsV6).To(Equal(&[]string{"-c", "d"}))
				fvar := false
				Expect(c.SNAT).To(Equal(&fvar))
				Expect(c.Name).To(Equal("test"))

				n, err := types.ParseCIDR("10.0.0.2/24")
				Expect(err).NotTo(HaveOccurred())
				Expect(c.ContIPv4).To(Equal(*n))
				n, err = types.ParseCIDR("2001:db8:1::2/64")
				Expect(err).NotTo(HaveOccurred())
				Expect(c.ContIPv6).To(Equal(*n))
			})

			It(fmt.Sprintf("[%s] correctly parses a DEL config", ver), func() {
				// When called with DEL, neither runtimeConfig nor prevResult may be specified
				configBytes := []byte(fmt.Sprintf(`{
					"name": "test",
					"type": "portmap",
					"cniVersion": "%s",
					"backend": "iptables",
					"snat": false,
					"conditionsV4": ["-a", "b"],
					"conditionsV6": ["-c", "d"]
				}`, ver))
				c, _, err := parseConfig(configBytes, "container")
				Expect(err).NotTo(HaveOccurred())
				Expect(c.CNIVersion).To(Equal(ver))
				Expect(c.ConditionsV4).To(Equal(&[]string{"-a", "b"}))
				Expect(c.ConditionsV6).To(Equal(&[]string{"-c", "d"}))
				fvar := false
				Expect(c.SNAT).To(Equal(&fvar))
				Expect(c.Name).To(Equal("test"))
			})

			It(fmt.Sprintf("[%s] fails with invalid mappings", ver), func() {
				configBytes := []byte(fmt.Sprintf(`{
					"name": "test",
					"type": "portmap",
					"cniVersion": "%s",
					"backend": "iptables",
					"snat": false,
					"conditionsV4": ["-a", "b"],
					"conditionsV6": ["-c", "d"],
					"runtimeConfig": {
						"portMappings": [
							{ "hostPort": 0, "containerPort": 80, "protocol": "tcp"}
						]
					}
				}`, ver))
				_, _, err := parseConfig(configBytes, "container")
				Expect(err).To(MatchError("Invalid host port number: 0"))
			})

			It(fmt.Sprintf("[%s] defaults to iptables when backend is not specified", ver), func() {
				// "defaults to iptables" is only true if iptables is installed
				// (or if neither iptables nor nftables is installed), but the
				// other unit tests would fail if iptables wasn't installed, so
				// we know it must be.
				configBytes := []byte(fmt.Sprintf(`{
					"name": "test",
					"type": "portmap",
					"cniVersion": "%s"
				}`, ver))
				c, _, err := parseConfig(configBytes, "container")
				Expect(err).NotTo(HaveOccurred())
				Expect(c.CNIVersion).To(Equal(ver))
				Expect(c.Backend).To(Equal(&iptablesBackend))
				Expect(c.Name).To(Equal("test"))
			})

			It(fmt.Sprintf("[%s] uses nftables if requested", ver), func() {
				configBytes := []byte(fmt.Sprintf(`{
					"name": "test",
					"type": "portmap",
					"cniVersion": "%s",
					"backend": "nftables"
				}`, ver))
				c, _, err := parseConfig(configBytes, "container")
				Expect(err).NotTo(HaveOccurred())
				Expect(c.CNIVersion).To(Equal(ver))
				Expect(c.Backend).To(Equal(&nftablesBackend))
				Expect(c.Name).To(Equal("test"))
			})

			It(fmt.Sprintf("[%s] allows nftables conditions if nftables is requested", ver), func() {
				configBytes := []byte(fmt.Sprintf(`{
					"name": "test",
					"type": "portmap",
					"cniVersion": "%s",
					"backend": "nftables",
					"conditionsV4": ["aaa", "bbbb"],
					"conditionsV6": ["ccc"]
				}`, ver))
				c, _, err := parseConfig(configBytes, "container")
				Expect(err).NotTo(HaveOccurred())
				Expect(c.CNIVersion).To(Equal(ver))
				Expect(c.Backend).To(Equal(&nftablesBackend))
				Expect(c.ConditionsV4).To(Equal(&[]string{"aaa", "bbbb"}))
				Expect(c.ConditionsV6).To(Equal(&[]string{"ccc"}))
				Expect(c.Name).To(Equal("test"))
			})

			It(fmt.Sprintf("[%s] rejects nftables options with 'backend: iptables'", ver), func() {
				configBytes := []byte(fmt.Sprintf(`{
					"name": "test",
					"type": "portmap",
					"cniVersion": "%s",
					"backend": "iptables",
					"conditionsV4": ["aaa", "bbbb"],
					"conditionsV6": ["ccc"]
				}`, ver))
				_, _, err := parseConfig(configBytes, "container")
				Expect(err).To(MatchError("iptables backend was requested but configuration contains nftables-specific options [conditionsV4 conditionsV6]"))
			})

			It(fmt.Sprintf("[%s] rejects iptables options with 'backend: nftables'", ver), func() {
				configBytes := []byte(fmt.Sprintf(`{
					"name": "test",
					"type": "portmap",
					"cniVersion": "%s",
					"backend": "nftables",
					"externalSetMarkChain": "KUBE-MARK-MASQ",
					"conditionsV4": ["-a", "b"],
					"conditionsV6": ["-c", "d"]
				}`, ver))
				_, _, err := parseConfig(configBytes, "container")
				Expect(err).To(MatchError("nftables backend was requested but configuration contains iptables-specific options [externalSetMarkChain conditionsV4 conditionsV6]"))
			})

			It(fmt.Sprintf("[%s] does not fail on missing prevResult interface index", ver), func() {
				configBytes := []byte(fmt.Sprintf(`{
					"name": "test",
					"type": "portmap",
					"cniVersion": "%s",
					"runtimeConfig": {
						"portMappings": [
							{ "hostPort": 8080, "containerPort": 80, "protocol": "tcp"}
						]
					},
					"conditionsV4": ["-a", "b"],
					"prevResult": {
						"interfaces": [
							{"name": "host"}
						],
						"ips": [
							{
								"version": "4",
								"address": "10.0.0.1/24",
								"gateway": "10.0.0.1"
							}
						]
					}
				}`, ver))
				_, _, err := parseConfig(configBytes, "container")
				Expect(err).NotTo(HaveOccurred())
			})
		})
	}
})
