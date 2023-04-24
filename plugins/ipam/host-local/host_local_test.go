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

package main

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	types100 "github.com/containernetworking/cni/pkg/types/100"
	"github.com/containernetworking/plugins/pkg/testutils"
	"github.com/containernetworking/plugins/plugins/ipam/host-local/backend/disk"
)

const LineBreak = "\r\n"

var _ = Describe("host-local Operations", func() {
	var tmpDir string
	const (
		ifname string = "eth0"
		nspath string = "/some/where"
	)

	BeforeEach(func() {
		var err error
		tmpDir, err = os.MkdirTemp("", "host-local_test")
		Expect(err).NotTo(HaveOccurred())
		tmpDir = filepath.ToSlash(tmpDir)
	})

	AfterEach(func() {
		os.RemoveAll(tmpDir)
	})

	for _, ver := range testutils.AllSpecVersions {
		// Redefine ver inside for scope so real value is picked up by each dynamically defined It()
		// See Gingkgo's "Patterns for dynamically generating tests" documentation.
		ver := ver

		It(fmt.Sprintf("[%s] allocates and releases addresses with ADD/DEL", ver), func() {
			err := os.WriteFile(filepath.Join(tmpDir, "resolv.conf"), []byte("nameserver 192.0.2.3"), 0o644)
			Expect(err).NotTo(HaveOccurred())

			conf := fmt.Sprintf(`{
			"cniVersion": "%s",
			"name": "mynet",
			"type": "ipvlan",
			"master": "foo0",
				"ipam": {
					"type": "host-local",
					"dataDir": "%s",
					"resolvConf": "%s/resolv.conf",
					"ranges": [
						[{ "subnet": "10.1.2.0/24" }, {"subnet": "10.2.2.0/24"}],
						[{ "subnet": "2001:db8:1::0/64" }]
					],
					"routes": [
						{"dst": "0.0.0.0/0"},
						{"dst": "::/0"},
						{"dst": "192.168.0.0/16", "gw": "1.1.1.1"},
						{"dst": "2001:db8:2::0/64", "gw": "2001:db8:3::1"}
					]
				}
			}`, ver, tmpDir, tmpDir)

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
					Address: mustCIDR("10.1.2.2/24"),
					Gateway: net.ParseIP("10.1.2.1"),
				}))

			Expect(*result.IPs[1]).To(Equal(
				types100.IPConfig{
					Address: mustCIDR("2001:db8:1::2/64"),
					Gateway: net.ParseIP("2001:db8:1::1"),
				},
			))
			Expect(result.IPs).To(HaveLen(2))

			for _, expectedRoute := range []*types.Route{
				{Dst: mustCIDR("0.0.0.0/0"), GW: nil},
				{Dst: mustCIDR("::/0"), GW: nil},
				{Dst: mustCIDR("192.168.0.0/16"), GW: net.ParseIP("1.1.1.1")},
				{Dst: mustCIDR("2001:db8:2::0/64"), GW: net.ParseIP("2001:db8:3::1")},
			} {
				found := false
				for _, foundRoute := range result.Routes {
					if foundRoute.String() == expectedRoute.String() {
						found = true
						break
					}
				}
				Expect(found).To(BeTrue())
			}

			ipFilePath1 := filepath.Join(tmpDir, "mynet", "10.1.2.2")
			contents, err := os.ReadFile(ipFilePath1)
			Expect(err).NotTo(HaveOccurred())
			Expect(string(contents)).To(Equal(args.ContainerID + LineBreak + ifname))

			ipFilePath2 := filepath.Join(tmpDir, disk.GetEscapedPath("mynet", "2001:db8:1::2"))
			contents, err = os.ReadFile(ipFilePath2)
			Expect(err).NotTo(HaveOccurred())
			Expect(string(contents)).To(Equal(args.ContainerID + LineBreak + ifname))

			lastFilePath1 := filepath.Join(tmpDir, "mynet", "last_reserved_ip.0")
			contents, err = os.ReadFile(lastFilePath1)
			Expect(err).NotTo(HaveOccurred())
			Expect(string(contents)).To(Equal("10.1.2.2"))

			lastFilePath2 := filepath.Join(tmpDir, "mynet", "last_reserved_ip.1")
			contents, err = os.ReadFile(lastFilePath2)
			Expect(err).NotTo(HaveOccurred())
			Expect(string(contents)).To(Equal("2001:db8:1::2"))
			// Release the IP
			err = testutils.CmdDelWithArgs(args, func() error {
				return cmdDel(args)
			})
			Expect(err).NotTo(HaveOccurred())

			_, err = os.Stat(ipFilePath1)
			Expect(err).To(HaveOccurred())
			_, err = os.Stat(ipFilePath2)
			Expect(err).To(HaveOccurred())
		})

		It(fmt.Sprintf("[%s] allocates and releases addresses on specific interface with ADD/DEL", ver), func() {
			const ifname1 string = "eth1"

			err := os.WriteFile(filepath.Join(tmpDir, "resolv.conf"), []byte("nameserver 192.0.2.3"), 0o644)
			Expect(err).NotTo(HaveOccurred())

			conf0 := fmt.Sprintf(`{
				"cniVersion": "%s",
				"name": "mynet0",
				"type": "ipvlan",
				"master": "foo0",
					"ipam": {
						"type": "host-local",
						"dataDir": "%s",
						"resolvConf": "%s/resolv.conf",
						"ranges": [
							[{ "subnet": "10.1.2.0/24" }]
						]
					}
			}`, ver, tmpDir, tmpDir)

			conf1 := fmt.Sprintf(`{
				"cniVersion": "%s",
				"name": "mynet1",
				"type": "ipvlan",
				"master": "foo1",
					"ipam": {
						"type": "host-local",
						"dataDir": "%s",
						"resolvConf": "%s/resolv.conf",
						"ranges": [
							[{ "subnet": "10.2.2.0/24" }]
						]
					}
			}`, ver, tmpDir, tmpDir)

			args0 := &skel.CmdArgs{
				ContainerID: "dummy",
				Netns:       nspath,
				IfName:      ifname,
				StdinData:   []byte(conf0),
			}

			// Allocate the IP
			r0, raw, err := testutils.CmdAddWithArgs(args0, func() error {
				return cmdAdd(args0)
			})
			Expect(err).NotTo(HaveOccurred())
			if testutils.SpecVersionHasIPVersion(ver) {
				Expect(strings.Index(string(raw), "\"version\":")).Should(BeNumerically(">", 0))
			}

			_, err = types100.GetResult(r0)
			Expect(err).NotTo(HaveOccurred())

			args1 := &skel.CmdArgs{
				ContainerID: "dummy",
				Netns:       nspath,
				IfName:      ifname1,
				StdinData:   []byte(conf1),
			}

			// Allocate the IP
			r1, raw, err := testutils.CmdAddWithArgs(args1, func() error {
				return cmdAdd(args1)
			})
			Expect(err).NotTo(HaveOccurred())
			if testutils.SpecVersionHasIPVersion(ver) {
				Expect(strings.Index(string(raw), "\"version\":")).Should(BeNumerically(">", 0))
			}

			_, err = types100.GetResult(r1)
			Expect(err).NotTo(HaveOccurred())

			ipFilePath0 := filepath.Join(tmpDir, "mynet0", "10.1.2.2")
			contents, err := os.ReadFile(ipFilePath0)
			Expect(err).NotTo(HaveOccurred())
			Expect(string(contents)).To(Equal(args0.ContainerID + LineBreak + ifname))

			ipFilePath1 := filepath.Join(tmpDir, "mynet1", "10.2.2.2")
			contents, err = os.ReadFile(ipFilePath1)
			Expect(err).NotTo(HaveOccurred())
			Expect(string(contents)).To(Equal(args1.ContainerID + LineBreak + ifname1))

			// Release the IP on ifname
			err = testutils.CmdDelWithArgs(args0, func() error {
				return cmdDel(args0)
			})
			Expect(err).NotTo(HaveOccurred())
			_, err = os.Stat(ipFilePath0)
			Expect(err).To(HaveOccurred())

			// reread ipFilePath1, ensure that ifname1 didn't get deleted
			contents, err = os.ReadFile(ipFilePath1)
			Expect(err).NotTo(HaveOccurred())
			Expect(string(contents)).To(Equal(args1.ContainerID + LineBreak + ifname1))

			// Release the IP on ifname1
			err = testutils.CmdDelWithArgs(args1, func() error {
				return cmdDel(args1)
			})
			Expect(err).NotTo(HaveOccurred())

			_, err = os.Stat(ipFilePath1)
			Expect(err).To(HaveOccurred())
		})

		It(fmt.Sprintf("[%s] repeat allocating addresses on specific interface for same container ID with ADD", ver), func() {
			conf := fmt.Sprintf(`{
				"cniVersion": "%s",
				"name": "mynet0",
				"type": "ipvlan",
				"master": "foo0",
					"ipam": {
						"type": "host-local",
						"dataDir": "%s",
						"ranges": [
							[{ "subnet": "10.1.2.0/24" }]
						]
					}
			}`, ver, tmpDir)

			args := &skel.CmdArgs{
				ContainerID: "dummy",
				Netns:       nspath,
				IfName:      ifname,
				StdinData:   []byte(conf),
			}

			args1 := &skel.CmdArgs{
				ContainerID: "dummy1",
				Netns:       nspath,
				IfName:      ifname,
				StdinData:   []byte(conf),
			}

			// Allocate the IP
			r0, raw, err := testutils.CmdAddWithArgs(args, func() error {
				return cmdAdd(args)
			})
			Expect(err).NotTo(HaveOccurred())
			if testutils.SpecVersionHasIPVersion(ver) {
				Expect(strings.Index(string(raw), "\"version\":")).Should(BeNumerically(">", 0))
			}

			result0, err := types100.GetResult(r0)
			Expect(err).NotTo(HaveOccurred())
			Expect(result0.IPs).Should(HaveLen(1))
			Expect(result0.IPs[0].Address.String()).Should(Equal("10.1.2.2/24"))

			// Allocate the IP with the same container ID
			_, _, err = testutils.CmdAddWithArgs(args, func() error {
				return cmdAdd(args)
			})
			Expect(err).To(HaveOccurred())

			// Allocate the IP with the another container ID
			r1, raw, err := testutils.CmdAddWithArgs(args1, func() error {
				return cmdAdd(args1)
			})
			Expect(err).NotTo(HaveOccurred())
			if testutils.SpecVersionHasIPVersion(ver) {
				Expect(strings.Index(string(raw), "\"version\":")).Should(BeNumerically(">", 0))
			}

			result1, err := types100.GetResult(r1)
			Expect(err).NotTo(HaveOccurred())
			Expect(result1.IPs).Should(HaveLen(1))
			Expect(result1.IPs[0].Address.String()).Should(Equal("10.1.2.3/24"))

			// Allocate the IP with the same container ID again
			_, _, err = testutils.CmdAddWithArgs(args, func() error {
				return cmdAdd(args)
			})
			Expect(err).To(HaveOccurred())

			ipFilePath := filepath.Join(tmpDir, "mynet0", "10.1.2.2")

			// Release the IPs
			err = testutils.CmdDelWithArgs(args, func() error {
				return cmdDel(args)
			})
			Expect(err).NotTo(HaveOccurred())
			_, err = os.Stat(ipFilePath)
			Expect(err).To(HaveOccurred())

			err = testutils.CmdDelWithArgs(args1, func() error {
				return cmdDel(args1)
			})
			Expect(err).NotTo(HaveOccurred())
		})

		It(fmt.Sprintf("[%s] verify DEL works on backwards compatible allocate", ver), func() {
			err := os.WriteFile(filepath.Join(tmpDir, "resolv.conf"), []byte("nameserver 192.0.2.3"), 0o644)
			Expect(err).NotTo(HaveOccurred())

			conf := fmt.Sprintf(`{
				"cniVersion": "%s",
				"name": "mynet",
				"type": "ipvlan",
				"master": "foo",
					"ipam": {
						"type": "host-local",
						"dataDir": "%s",
						"resolvConf": "%s/resolv.conf",
						"ranges": [
							[{ "subnet": "10.1.2.0/24" }]
						]
					}
			}`, ver, tmpDir, tmpDir)

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

			_, err = types100.GetResult(r)
			Expect(err).NotTo(HaveOccurred())

			ipFilePath := filepath.Join(tmpDir, "mynet", "10.1.2.2")
			contents, err := os.ReadFile(ipFilePath)
			Expect(err).NotTo(HaveOccurred())
			Expect(string(contents)).To(Equal(args.ContainerID + LineBreak + ifname))
			err = os.WriteFile(ipFilePath, []byte(strings.TrimSpace(args.ContainerID)), 0o644)
			Expect(err).NotTo(HaveOccurred())

			err = testutils.CmdDelWithArgs(args, func() error {
				return cmdDel(args)
			})
			Expect(err).NotTo(HaveOccurred())
			_, err = os.Stat(ipFilePath)
			Expect(err).To(HaveOccurred())
		})

		It(fmt.Sprintf("[%s] doesn't error when passed an unknown ID on DEL", ver), func() {
			conf := fmt.Sprintf(`{
				"cniVersion": "%s",
				"name": "mynet",
				"type": "ipvlan",
				"master": "foo0",
				"ipam": {
					"type": "host-local",
					"subnet": "10.1.2.0/24",
					"dataDir": "%s"
				}
			}`, ver, tmpDir)

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

		It(fmt.Sprintf("[%s] ignores whitespace in disk files", ver), func() {
			conf := fmt.Sprintf(`{
				"cniVersion": "%s",
				"name": "mynet",
				"type": "ipvlan",
				"master": "foo0",
				"ipam": {
					"type": "host-local",
					"subnet": "10.1.2.0/24",
					"dataDir": "%s"
				}
			}`, ver, tmpDir)

			args := &skel.CmdArgs{
				ContainerID: "   dummy\n ",
				Netns:       nspath,
				IfName:      ifname,
				StdinData:   []byte(conf),
			}

			// Allocate the IP
			r, _, err := testutils.CmdAddWithArgs(args, func() error {
				return cmdAdd(args)
			})
			Expect(err).NotTo(HaveOccurred())

			result, err := types100.GetResult(r)
			Expect(err).NotTo(HaveOccurred())

			ipFilePath := filepath.Join(tmpDir, "mynet", result.IPs[0].Address.IP.String())
			contents, err := os.ReadFile(ipFilePath)
			Expect(err).NotTo(HaveOccurred())
			Expect(string(contents)).To(Equal("dummy" + LineBreak + ifname))

			// Release the IP
			err = testutils.CmdDelWithArgs(args, func() error {
				return cmdDel(args)
			})
			Expect(err).NotTo(HaveOccurred())

			_, err = os.Stat(ipFilePath)
			Expect(err).To(HaveOccurred())
		})

		It(fmt.Sprintf("[%s] does not output an error message upon initial subnet creation", ver), func() {
			conf := fmt.Sprintf(`{
				"cniVersion": "%s",
				"name": "mynet",
				"type": "ipvlan",
				"master": "foo0",
				"ipam": {
					"type": "host-local",
					"subnet": "10.1.2.0/24",
					"dataDir": "%s"
				}
			}`, ver, tmpDir)

			args := &skel.CmdArgs{
				ContainerID: "testing",
				Netns:       nspath,
				IfName:      ifname,
				StdinData:   []byte(conf),
			}

			// Allocate the IP
			_, out, err := testutils.CmdAddWithArgs(args, func() error {
				return cmdAdd(args)
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(strings.Index(string(out), "Error retrieving last reserved ip")).To(Equal(-1))
		})

		It(fmt.Sprintf("[%s] allocates a custom IP when requested by config args", ver), func() {
			conf := fmt.Sprintf(`{
				"cniVersion": "%s",
				"name": "mynet",
				"type": "ipvlan",
				"master": "foo0",
				"ipam": {
					"type": "host-local",
					"dataDir": "%s",
					"ranges": [
						[{ "subnet": "10.1.2.0/24" }]
					]
				},
				"args": {
					"cni": {
						"ips": ["10.1.2.88"]
					}
				}
			}`, ver, tmpDir)

			args := &skel.CmdArgs{
				ContainerID: "dummy",
				Netns:       nspath,
				IfName:      ifname,
				StdinData:   []byte(conf),
			}

			// Allocate the IP
			r, _, err := testutils.CmdAddWithArgs(args, func() error {
				return cmdAdd(args)
			})
			Expect(err).NotTo(HaveOccurred())
			result, err := types100.GetResult(r)
			Expect(err).NotTo(HaveOccurred())
			Expect(result.IPs).To(HaveLen(1))
			Expect(result.IPs[0].Address.IP).To(Equal(net.ParseIP("10.1.2.88")))
		})

		It(fmt.Sprintf("[%s] allocates custom IPs from multiple ranges", ver), func() {
			err := os.WriteFile(filepath.Join(tmpDir, "resolv.conf"), []byte("nameserver 192.0.2.3"), 0o644)
			Expect(err).NotTo(HaveOccurred())

			conf := fmt.Sprintf(`{
				"cniVersion": "%s",
				"name": "mynet",
				"type": "ipvlan",
				"master": "foo0",
				"ipam": {
					"type": "host-local",
					"dataDir": "%s",
					"ranges": [
						[{ "subnet": "10.1.2.0/24" }],
						[{ "subnet": "10.1.3.0/24" }]
					]
				},
				"args": {
					"cni": {
						"ips": ["10.1.2.88", "10.1.3.77"]
					}
				}
			}`, ver, tmpDir)

			args := &skel.CmdArgs{
				ContainerID: "dummy",
				Netns:       nspath,
				IfName:      ifname,
				StdinData:   []byte(conf),
			}

			// Allocate the IP
			r, _, err := testutils.CmdAddWithArgs(args, func() error {
				return cmdAdd(args)
			})
			if !testutils.SpecVersionHasMultipleIPs(ver) {
				errStr := fmt.Sprintf("CNI version %s does not support more than 1 address per family", ver)
				Expect(err).To(MatchError(errStr))
			} else {
				Expect(err).NotTo(HaveOccurred())
				result, err := types100.GetResult(r)
				Expect(err).NotTo(HaveOccurred())
				Expect(result.IPs).To(HaveLen(2))
				Expect(result.IPs[0].Address.IP).To(Equal(net.ParseIP("10.1.2.88")))
				Expect(result.IPs[1].Address.IP).To(Equal(net.ParseIP("10.1.3.77")))
			}
		})

		It(fmt.Sprintf("[%s] allocates custom IPs from multiple protocols", ver), func() {
			err := os.WriteFile(filepath.Join(tmpDir, "resolv.conf"), []byte("nameserver 192.0.2.3"), 0o644)
			Expect(err).NotTo(HaveOccurred())

			conf := fmt.Sprintf(`{
				"cniVersion": "%s",
				"name": "mynet",
				"type": "ipvlan",
				"master": "foo0",
				"ipam": {
					"type": "host-local",
					"dataDir": "%s",
					"ranges": [
						[{"subnet":"172.16.1.0/24"}, { "subnet": "10.1.2.0/24" }],
						[{ "subnet": "2001:db8:1::/48" }]
					]
				},
				"args": {
					"cni": {
						"ips": ["10.1.2.88", "2001:db8:1::999"]
					}
				}
			}`, ver, tmpDir)

			args := &skel.CmdArgs{
				ContainerID: "dummy",
				Netns:       nspath,
				IfName:      ifname,
				StdinData:   []byte(conf),
			}

			// Allocate the IP
			r, _, err := testutils.CmdAddWithArgs(args, func() error {
				return cmdAdd(args)
			})
			Expect(err).NotTo(HaveOccurred())
			result, err := types100.GetResult(r)
			Expect(err).NotTo(HaveOccurred())
			Expect(result.IPs).To(HaveLen(2))
			Expect(result.IPs[0].Address.IP).To(Equal(net.ParseIP("10.1.2.88")))
			Expect(result.IPs[1].Address.IP).To(Equal(net.ParseIP("2001:db8:1::999")))
		})

		It(fmt.Sprintf("[%s] fails if a requested custom IP is not used", ver), func() {
			conf := fmt.Sprintf(`{
				"cniVersion": "%s",
				"name": "mynet",
				"type": "ipvlan",
				"master": "foo0",
				"ipam": {
					"type": "host-local",
					"dataDir": "%s",
					"ranges": [
						[{ "subnet": "10.1.2.0/24" }],
						[{ "subnet": "10.1.3.0/24" }]
					]
				},
				"args": {
					"cni": {
						"ips": ["10.1.2.88", "10.1.2.77"]
					}
				}
			}`, ver, tmpDir)

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
			if !testutils.SpecVersionHasMultipleIPs(ver) {
				errStr := fmt.Sprintf("CNI version %s does not support more than 1 address per family", ver)
				Expect(err).To(MatchError(errStr))
			} else {
				Expect(err).To(HaveOccurred())
				// Need to match prefix, because ordering is not guaranteed
				Expect(err.Error()).To(HavePrefix("failed to allocate all requested IPs: 10.1.2."))
			}
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
