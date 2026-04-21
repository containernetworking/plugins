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
	"net"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	types100 "github.com/containernetworking/cni/pkg/types/100"
	"github.com/containernetworking/plugins/pkg/testutils"
)

var _ = Describe("static Operations", func() {
	for _, ver := range testutils.AllSpecVersions {
		// Redefine ver inside for scope so real value is picked up by each dynamically defined It()
		// See Gingkgo's "Patterns for dynamically generating tests" documentation.
		ver := ver

		It(fmt.Sprintf("[%s] allocates and releases addresses with ADD/DEL", ver), func() {
			const ifname string = "eth0"
			const nspath string = "/some/where"

			conf := fmt.Sprintf(`{
				"cniVersion": "%s",
				"name": "mynet",
				"type": "ipvlan",
				"master": "foo0",
				"ipam": {
					"type": "static",
					"addresses": [ {
							"address": "10.10.0.1/24",
							"gateway": "10.10.0.254"
						},
						{
							"address": "3ffe:ffff:0:01ff::1/64",
							"gateway": "3ffe:ffff:0::1"
						}],
					"routes": [
						{ "dst": "0.0.0.0/0" },
						{ "dst": "192.168.0.0/16", "gw": "10.10.5.1" },
						{ "dst": "3ffe:ffff:0:01ff::1/64" }],
					"dns": {
						"nameservers" : ["8.8.8.8"],
						"domain": "example.com",
						"search": [ "example.com" ]
					}
				}
			}`, ver)

			args := &skel.CmdArgs{
				ContainerID: "dummy",
				Netns:       nspath,
				IfName:      ifname,
				StdinData:   []byte(conf),
			}

			// Allocate the IP
			r, raw, err := testutils.CmdAddWithArgs(args, func() error {
				return cmdAdd(args)
			})
			Expect(err).NotTo(HaveOccurred())
			if testutils.SpecVersionHasIPVersion(ver) {
				Expect(strings.Index(string(raw), "\"version\":")).Should(BeNumerically(">", 0))
			}

			result, err := types100.GetResult(r)
			Expect(err).NotTo(HaveOccurred())

			// Gomega is cranky about slices with different caps
			Expect(*result.IPs[0]).To(Equal(
				types100.IPConfig{
					Address: mustCIDR("10.10.0.1/24"),
					Gateway: net.ParseIP("10.10.0.254"),
				}))

			Expect(*result.IPs[1]).To(Equal(
				types100.IPConfig{
					Address: mustCIDR("3ffe:ffff:0:01ff::1/64"),
					Gateway: net.ParseIP("3ffe:ffff:0::1"),
				},
			))
			Expect(result.IPs).To(HaveLen(2))

			Expect(result.Routes).To(Equal([]*types.Route{
				{Dst: mustCIDR("0.0.0.0/0")},
				{Dst: mustCIDR("192.168.0.0/16"), GW: net.ParseIP("10.10.5.1")},
				{Dst: mustCIDR("3ffe:ffff:0:01ff::1/64")},
			}))

			// Release the IP
			err = testutils.CmdDelWithArgs(args, func() error {
				return cmdDel(args)
			})
			Expect(err).NotTo(HaveOccurred())
		})

		It(fmt.Sprintf("[%s] doesn't error when passed an unknown ID on DEL", ver), func() {
			const ifname string = "eth0"
			const nspath string = "/some/where"

			conf := fmt.Sprintf(`{
				"cniVersion": "%s",
				"name": "mynet",
				"type": "ipvlan",
				"master": "foo0",
				"ipam": {
					"type": "static",
					"addresses": [ {
						"address": "10.10.0.1/24",
						"gateway": "10.10.0.254"
					},
					{
						"address": "3ffe:ffff:0:01ff::1/64",
						"gateway": "3ffe:ffff:0::1"
					}],
					"routes": [
					{ "dst": "0.0.0.0/0" },
					{ "dst": "192.168.0.0/16", "gw": "10.10.5.1" },
					{ "dst": "3ffe:ffff:0:01ff::1/64" }],
					"dns": {
						"nameservers" : ["8.8.8.8"],
						"domain": "example.com",
						"search": [ "example.com" ]
					}
				}
			}`, ver)

			args := &skel.CmdArgs{
				ContainerID: "dummy",
				Netns:       nspath,
				IfName:      ifname,
				StdinData:   []byte(conf),
			}

			// Release the IP
			err := testutils.CmdDelWithArgs(args, func() error {
				return cmdDel(args)
			})
			Expect(err).NotTo(HaveOccurred())
		})

		It(fmt.Sprintf("[%s] allocates and releases addresses with ADD/DEL, with ENV variables", ver), func() {
			const ifname string = "eth0"
			const nspath string = "/some/where"

			conf := fmt.Sprintf(`{
				"cniVersion": "%s",
				"name": "mynet",
				"type": "ipvlan",
				"master": "foo0",
				"ipam": {
					"type": "static",
					"routes": [
						{ "dst": "0.0.0.0/0" },
						{ "dst": "192.168.0.0/16", "gw": "10.10.5.1" }],
					"dns": {
						"nameservers" : ["8.8.8.8"],
						"domain": "example.com",
						"search": [ "example.com" ]
					}
				}
			}`, ver)

			args := &skel.CmdArgs{
				ContainerID: "dummy",
				Netns:       nspath,
				IfName:      ifname,
				StdinData:   []byte(conf),
				Args:        "IP=10.10.0.1/24;GATEWAY=10.10.0.254",
			}

			// Allocate the IP
			r, raw, err := testutils.CmdAddWithArgs(args, func() error {
				return cmdAdd(args)
			})
			Expect(err).NotTo(HaveOccurred())
			if testutils.SpecVersionHasIPVersion(ver) {
				Expect(strings.Index(string(raw), "\"version\":")).Should(BeNumerically(">", 0))
			}

			result, err := types100.GetResult(r)
			Expect(err).NotTo(HaveOccurred())

			// Gomega is cranky about slices with different caps
			Expect(*result.IPs[0]).To(Equal(
				types100.IPConfig{
					Address: mustCIDR("10.10.0.1/24"),
					Gateway: net.ParseIP("10.10.0.254"),
				}))

			Expect(result.IPs).To(HaveLen(1))

			Expect(result.Routes).To(Equal([]*types.Route{
				{Dst: mustCIDR("0.0.0.0/0")},
				{Dst: mustCIDR("192.168.0.0/16"), GW: net.ParseIP("10.10.5.1")},
			}))

			// Release the IP
			err = testutils.CmdDelWithArgs(args, func() error {
				return cmdDel(args)
			})
			Expect(err).NotTo(HaveOccurred())
		})

		It(fmt.Sprintf("[%s] allocates and releases multiple addresses with ADD/DEL, with ENV variables", ver), func() {
			const ifname string = "eth0"
			const nspath string = "/some/where"

			conf := fmt.Sprintf(`{
				"cniVersion": "%s",
				"name": "mynet",
				"type": "ipvlan",
				"master": "foo0",
				"ipam": {
					"type": "static"
				}
			}`, ver)

			args := &skel.CmdArgs{
				ContainerID: "dummy",
				Netns:       nspath,
				IfName:      ifname,
				StdinData:   []byte(conf),
				Args:        "IP=10.10.0.1/24,11.11.0.1/24;GATEWAY=10.10.0.254",
			}

			// Allocate the IP
			r, raw, err := testutils.CmdAddWithArgs(args, func() error {
				return cmdAdd(args)
			})
			if !testutils.SpecVersionHasMultipleIPs(ver) {
				errStr := fmt.Sprintf("CNI version %s does not support more than 1 address per family", ver)
				Expect(err).To(MatchError(errStr))
				return
			}

			Expect(err).NotTo(HaveOccurred())
			if testutils.SpecVersionHasIPVersion(ver) {
				Expect(strings.Index(string(raw), "\"version\":")).Should(BeNumerically(">", 0))
			}

			result, err := types100.GetResult(r)
			Expect(err).NotTo(HaveOccurred())

			// Gomega is cranky about slices with different caps
			Expect(*result.IPs[0]).To(Equal(
				types100.IPConfig{
					Address: mustCIDR("10.10.0.1/24"),
					Gateway: net.ParseIP("10.10.0.254"),
				}))
			Expect(*result.IPs[1]).To(Equal(
				types100.IPConfig{
					Address: mustCIDR("11.11.0.1/24"),
					Gateway: nil,
				}))

			Expect(result.IPs).To(HaveLen(2))

			// Release the IP
			err = testutils.CmdDelWithArgs(args, func() error {
				return cmdDel(args)
			})
			Expect(err).NotTo(HaveOccurred())
		})

		It(fmt.Sprintf("[%s] allocates and releases multiple addresses with ADD/DEL, from RuntimeConfig", ver), func() {
			const ifname string = "eth0"
			const nspath string = "/some/where"

			conf := fmt.Sprintf(`{
				"cniVersion": "%s",
				"name": "mynet",
				"type": "ipvlan",
				"master": "foo0",
				"capabilities": {"ips": true},
				"ipam": {
					"type": "static",
					"routes": [
					{ "dst": "0.0.0.0/0", "gw": "10.10.0.254" },
					{ "dst": "3ffe:ffff:0:01ff::1/64",
		                          "gw": "3ffe:ffff:0::1" } ],
					  "dns": {
						"nameservers" : ["8.8.8.8"],
						"domain": "example.com",
						"search": [ "example.com" ]
					}
				},
				"RuntimeConfig": {
					"ips" : ["10.10.0.1/24", "3ffe:ffff:0:01ff::1/64"]
				}
			}`, ver)

			args := &skel.CmdArgs{
				ContainerID: "dummy",
				Netns:       nspath,
				IfName:      ifname,
				StdinData:   []byte(conf),
			}

			// Allocate the IP
			r, raw, err := testutils.CmdAddWithArgs(args, func() error {
				return cmdAdd(args)
			})
			Expect(err).NotTo(HaveOccurred())
			if testutils.SpecVersionHasIPVersion(ver) {
				Expect(strings.Index(string(raw), "\"version\":")).Should(BeNumerically(">", 0))
			}

			result, err := types100.GetResult(r)
			Expect(err).NotTo(HaveOccurred())

			// Gomega is cranky about slices with different caps
			Expect(*result.IPs[0]).To(Equal(
				types100.IPConfig{
					Address: mustCIDR("10.10.0.1/24"),
				}))
			Expect(*result.IPs[1]).To(Equal(
				types100.IPConfig{
					Address: mustCIDR("3ffe:ffff:0:01ff::1/64"),
				},
			))
			Expect(result.IPs).To(HaveLen(2))
			Expect(result.Routes).To(Equal([]*types.Route{
				{Dst: mustCIDR("0.0.0.0/0"), GW: net.ParseIP("10.10.0.254")},
				{Dst: mustCIDR("3ffe:ffff:0:01ff::1/64"), GW: net.ParseIP("3ffe:ffff:0::1")},
			}))

			// Release the IP
			err = testutils.CmdDelWithArgs(args, func() error {
				return cmdDel(args)
			})
			Expect(err).NotTo(HaveOccurred())
		})

		It(fmt.Sprintf("[%s] allocates and releases multiple addresses with ADD/DEL, from args", ver), func() {
			const ifname string = "eth0"
			const nspath string = "/some/where"

			conf := fmt.Sprintf(`{
				"cniVersion": "%s",
				"name": "mynet",
				"type": "ipvlan",
				"master": "foo0",
				"ipam": {
					"type": "static",
					"routes": [
					{ "dst": "0.0.0.0/0", "gw": "10.10.0.254" },
					{ "dst": "3ffe:ffff:0:01ff::1/64",
		                          "gw": "3ffe:ffff:0::1" } ],
					  "dns": {
						"nameservers" : ["8.8.8.8"],
						"domain": "example.com",
						"search": [ "example.com" ]
					}
				},
				"args": {
					"cni": {
						"ips" : ["10.10.0.1/24", "3ffe:ffff:0:01ff::1/64"]
					}
				}
			}`, ver)

			args := &skel.CmdArgs{
				ContainerID: "dummy",
				Netns:       nspath,
				IfName:      ifname,
				StdinData:   []byte(conf),
			}

			// Allocate the IP
			r, raw, err := testutils.CmdAddWithArgs(args, func() error {
				return cmdAdd(args)
			})
			Expect(err).NotTo(HaveOccurred())
			if testutils.SpecVersionHasIPVersion(ver) {
				Expect(strings.Index(string(raw), "\"version\":")).Should(BeNumerically(">", 0))
			}

			result, err := types100.GetResult(r)
			Expect(err).NotTo(HaveOccurred())

			// Gomega is cranky about slices with different caps
			Expect(*result.IPs[0]).To(Equal(
				types100.IPConfig{
					Address: mustCIDR("10.10.0.1/24"),
				}))
			Expect(*result.IPs[1]).To(Equal(
				types100.IPConfig{
					Address: mustCIDR("3ffe:ffff:0:01ff::1/64"),
				},
			))
			Expect(result.IPs).To(HaveLen(2))
			Expect(result.Routes).To(Equal([]*types.Route{
				{Dst: mustCIDR("0.0.0.0/0"), GW: net.ParseIP("10.10.0.254")},
				{Dst: mustCIDR("3ffe:ffff:0:01ff::1/64"), GW: net.ParseIP("3ffe:ffff:0::1")},
			}))

			// Release the IP
			err = testutils.CmdDelWithArgs(args, func() error {
				return cmdDel(args)
			})
			Expect(err).NotTo(HaveOccurred())
		})

		It(fmt.Sprintf("[%s] allocates and releases multiple addresses with ADD/DEL, from RuntimeConfig/ARGS/CNI_ARGS", ver), func() {
			const ifname string = "eth0"
			const nspath string = "/some/where"

			conf := fmt.Sprintf(`{
				"cniVersion": "%s",
				"name": "mynet",
				"type": "ipvlan",
				"master": "foo0",
				"capabilities": {"ips": true},
				"ipam": {
					"type": "static",
					"routes": [
					{ "dst": "0.0.0.0/0", "gw": "10.10.0.254" },
					{ "dst": "3ffe:ffff:0:01ff::1/64",
		                          "gw": "3ffe:ffff:0::1" } ],
					  "dns": {
						"nameservers" : ["8.8.8.8"],
						"domain": "example.com",
						"search": [ "example.com" ]
					}
				},
				"RuntimeConfig": {
					"ips" : ["10.10.0.1/24", "3ffe:ffff:0:01ff::1/64"]
				},
				"args": {
					"cni": {
						"ips" : ["10.10.0.2/24", "3ffe:ffff:0:01ff::2/64"]
					}
				}
			}`, ver)

			args := &skel.CmdArgs{
				ContainerID: "dummy",
				Netns:       nspath,
				IfName:      ifname,
				StdinData:   []byte(conf),
				Args:        "IP=10.10.0.3/24,11.11.0.3/24;GATEWAY=10.10.0.254",
			}

			// Allocate the IP
			r, raw, err := testutils.CmdAddWithArgs(args, func() error {
				return cmdAdd(args)
			})
			Expect(err).NotTo(HaveOccurred())
			if testutils.SpecVersionHasIPVersion(ver) {
				Expect(strings.Index(string(raw), "\"version\":")).Should(BeNumerically(">", 0))
			}

			result, err := types100.GetResult(r)
			Expect(err).NotTo(HaveOccurred())

			// only addresses in runtimeConfig configured because of its priorities
			Expect(*result.IPs[0]).To(Equal(
				types100.IPConfig{
					Address: mustCIDR("10.10.0.1/24"),
				}))
			Expect(*result.IPs[1]).To(Equal(
				types100.IPConfig{
					Address: mustCIDR("3ffe:ffff:0:01ff::1/64"),
				},
			))
			Expect(result.IPs).To(HaveLen(2))
			Expect(result.Routes).To(Equal([]*types.Route{
				{Dst: mustCIDR("0.0.0.0/0"), GW: net.ParseIP("10.10.0.254")},
				{Dst: mustCIDR("3ffe:ffff:0:01ff::1/64"), GW: net.ParseIP("3ffe:ffff:0::1")},
			}))

			// Release the IP
			err = testutils.CmdDelWithArgs(args, func() error {
				return cmdDel(args)
			})
			Expect(err).NotTo(HaveOccurred())
		})

		It(fmt.Sprintf("[%s] is returning an error on missing ipam key when args are set", ver), func() {
			const ifname string = "eth0"
			const nspath string = "/some/where"
			conf := fmt.Sprintf(`{
				"cniVersion": "%s",
				"name": "mynet",
				"type": "ipvlan",
				"master": "foo0"
			}`, ver)

			args := &skel.CmdArgs{
				ContainerID: "dummy",
				Netns:       nspath,
				IfName:      ifname,
				StdinData:   []byte(conf),
				Args:        "IP=10.10.0.1/24;GATEWAY=10.10.0.254",
			}

			// Allocate the IP
			_, _, err := testutils.CmdAddWithArgs(args, func() error {
				return cmdAdd(args)
			})
			Expect(err).Should(MatchError("IPAM config missing 'ipam' key"))
		})

		It(fmt.Sprintf("[%s] is returning an error on missing ipam key when runtimeConfig is set", ver), func() {
			const ifname string = "eth0"
			const nspath string = "/some/where"
			conf := fmt.Sprintf(`{
				"cniVersion": "%s",
				"name": "mynet",
				"type": "ipvlan",
				"master": "foo0",
				"runtimeConfig": {
					"ips": ["10.10.0.1/24"]
				}
			}`, ver)

			args := &skel.CmdArgs{
				ContainerID: "dummy",
				Netns:       nspath,
				IfName:      ifname,
				StdinData:   []byte(conf),
			}

			// Allocate the IP
			_, _, err := testutils.CmdAddWithArgs(args, func() error {
				return cmdAdd(args)
			})
			Expect(err).Should(MatchError("IPAM config missing 'ipam' key"))
		})

		It(fmt.Sprintf("[%s] errors when passed an invalid CIDR via ipam config", ver), func() {
			const ifname string = "eth0"
			const nspath string = "/some/where"
			const ipStr string = "10.10.0.1"

			conf := fmt.Sprintf(`{
				"cniVersion": "%s",
				"name": "mynet",
				"type": "bridge",
				"ipam": {
					"type": "static",
					"addresses": [ {
						"address": "%s"
					}]
				}
			}`, ver, ipStr)

			args := &skel.CmdArgs{
				ContainerID: "dummy",
				Netns:       nspath,
				IfName:      ifname,
				StdinData:   []byte(conf),
			}

			// Allocate the IP
			_, _, err := testutils.CmdAddWithArgs(args, func() error {
				return cmdAdd(args)
			})
			Expect(err).Should(MatchError(
				fmt.Sprintf("the 'address' field is expected to be in CIDR notation, got: '%s'", ipStr)))
		})

		It(fmt.Sprintf("[%s] errors when passed an invalid CIDR via Args", ver), func() {
			const ifname string = "eth0"
			const nspath string = "/some/where"
			const ipStr string = "10.10.0.1"

			conf := fmt.Sprintf(`{
				"cniVersion": "%s",
				"name": "mynet",
				"type": "bridge",
				"ipam": {
					"type": "static",
					"routes": [{ "dst": "0.0.0.0/0" }]
				}
			}`, ver)

			args := &skel.CmdArgs{
				ContainerID: "dummy",
				Netns:       nspath,
				IfName:      ifname,
				StdinData:   []byte(conf),
				Args:        fmt.Sprintf("IP=%s", ipStr),
			}

			// Allocate the IP
			_, _, err := testutils.CmdAddWithArgs(args, func() error {
				return cmdAdd(args)
			})
			Expect(err).Should(MatchError(
				fmt.Sprintf("the 'ip' field is expected to be in CIDR notation, got: '%s'", ipStr)))
		})

		It(fmt.Sprintf("[%s] errors when passed an invalid CIDR via CNI_ARGS", ver), func() {
			const ifname string = "eth0"
			const nspath string = "/some/where"
			const ipStr string = "10.10.0.1"

			conf := fmt.Sprintf(`{
				"cniVersion": "%s",
				"name": "mynet",
				"type": "bridge",
				"ipam": {
					"type": "static",
					"routes": [{ "dst": "0.0.0.0/0" }]
				},
				"args": {
					"cni": {
						"ips" : ["%s"]
					}
				}
			}`, ver, ipStr)

			args := &skel.CmdArgs{
				ContainerID: "dummy",
				Netns:       nspath,
				IfName:      ifname,
				StdinData:   []byte(conf),
			}

			// Allocate the IP
			_, _, err := testutils.CmdAddWithArgs(args, func() error {
				return cmdAdd(args)
			})
			Expect(err).Should(MatchError(
				fmt.Sprintf("an entry in the 'ips' field is NOT in CIDR notation, got: '%s'", ipStr)))
		})

		It(fmt.Sprintf("[%s] errors when passed an invalid CIDR via RuntimeConfig", ver), func() {
			const ifname string = "eth0"
			const nspath string = "/some/where"
			const ipStr string = "10.10.0.1"

			conf := fmt.Sprintf(`{
				"cniVersion": "%s",
				"name": "mynet",
				"type": "bridge",
				"ipam": {
					"type": "static",
					"routes": [{ "dst": "0.0.0.0/0" }]
				},
				"RuntimeConfig": {
					"ips" : ["%s"]
				}
			}`, ver, ipStr)

			args := &skel.CmdArgs{
				ContainerID: "dummy",
				Netns:       nspath,
				IfName:      ifname,
				StdinData:   []byte(conf),
			}

			// Allocate the IP
			_, _, err := testutils.CmdAddWithArgs(args, func() error {
				return cmdAdd(args)
			})
			Expect(err).Should(MatchError(
				fmt.Sprintf("an entry in the 'ips' field is NOT in CIDR notation, got: '%s'", ipStr)))
		})
	}
})

func mustCIDR(s string) net.IPNet {
	ip, n, err := net.ParseCIDR(s)
	n.IP = ip
	if err != nil {
		Fail(err.Error())
	}

	return *n
}
