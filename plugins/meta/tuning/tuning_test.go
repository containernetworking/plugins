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
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	types100 "github.com/containernetworking/cni/pkg/types/100"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/containernetworking/plugins/pkg/testutils"
)

func buildOneConfig(cniVersion string, orig *TuningConf, prevResult types.Result) ([]byte, error) {
	var err error

	inject := map[string]interface{}{
		"name":       "testConfig",
		"cniVersion": cniVersion,
	}
	// Add previous plugin result
	if prevResult != nil {
		inject["prevResult"] = prevResult
	}

	// Ensure every config uses the same name and version
	config := make(map[string]interface{})

	confBytes, err := json.Marshal(orig)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(confBytes, &config)
	if err != nil {
		return nil, fmt.Errorf("unmarshal existing network bytes: %s", err)
	}

	for key, value := range inject {
		config[key] = value
	}

	newBytes, err := json.Marshal(config)
	if err != nil {
		return nil, err
	}

	conf := &TuningConf{}
	if err := json.Unmarshal(newBytes, &conf); err != nil {
		return nil, fmt.Errorf("error parsing configuration: %s", err)
	}

	return newBytes, nil
}

func createSysctlAllowFile(sysctls []string) error {
	err := os.MkdirAll(defaultAllowlistDir, 0o755)
	if err != nil {
		return err
	}
	f, err := os.Create(filepath.Join(defaultAllowlistDir, defaultAllowlistFile))
	if err != nil {
		return err
	}
	for _, sysctl := range sysctls {
		_, err = f.WriteString(fmt.Sprintf("%s\n", sysctl))
		if err != nil {
			return err
		}
	}
	return nil
}

var _ = Describe("tuning plugin", func() {
	var originalNS, targetNS ns.NetNS
	const IFNAME string = "dummy0"
	var beforeConf configToRestore

	BeforeEach(func() {
		// Create a new NetNS so we don't modify the host
		var err error
		originalNS, err = testutils.NewNS()
		Expect(err).NotTo(HaveOccurred())

		targetNS, err = testutils.NewNS()
		Expect(err).NotTo(HaveOccurred())

		err = originalNS.Do(func(ns.NetNS) error {
			defer GinkgoRecover()

			linkAttrs := netlink.NewLinkAttrs()
			linkAttrs.Name = IFNAME
			err = netlink.LinkAdd(&netlink.Dummy{
				LinkAttrs: linkAttrs,
			})
			Expect(err).NotTo(HaveOccurred())
			link, err := netlink.LinkByName(IFNAME)
			Expect(err).NotTo(HaveOccurred())

			beforeConf.Mac = link.Attrs().HardwareAddr.String()
			beforeConf.Mtu = link.Attrs().MTU
			beforeConf.Promisc = new(bool)
			*beforeConf.Promisc = (link.Attrs().Promisc != 0)
			beforeConf.Allmulti = new(bool)
			*beforeConf.Allmulti = (link.Attrs().RawFlags&unix.IFF_ALLMULTI != 0)
			beforeConf.TxQLen = new(int)
			*beforeConf.TxQLen = link.Attrs().TxQLen
			return nil
		})
		Expect(err).NotTo(HaveOccurred())
		sysctlDuplicatesMap = map[sysctlKey]interface{}{}
	})

	AfterEach(func() {
		Expect(originalNS.Close()).To(Succeed())
		Expect(testutils.UnmountNS(originalNS)).To(Succeed())
		Expect(targetNS.Close()).To(Succeed())
		Expect(testutils.UnmountNS(targetNS)).To(Succeed())
		os.RemoveAll(defaultAllowlistDir)
	})

	for _, ver := range []string{"0.3.0", "0.3.1", "0.4.0", "1.0.0"} {
		// Redefine ver inside for scope so real value is picked up by each dynamically defined It()
		// See Gingkgo's "Patterns for dynamically generating tests" documentation.
		ver := ver

		It(fmt.Sprintf("[%s] passes prevResult through unchanged", ver), func() {
			conf := []byte(fmt.Sprintf(`{
				"name": "test",
				"type": "tuning",
				"cniVersion": "%s",
				"sysctl": {
					"net.ipv4.conf.all.log_martians": "1"
				},
				"prevResult": {
					"interfaces": [
						{"name": "dummy0", "sandbox":"netns"}
					],
					"ips": [
						{
							"version": "4",
							"address": "10.0.0.2/24",
							"gateway": "10.0.0.1",
							"interface": 0
						}
					]
				}
			}`, ver))

			args := &skel.CmdArgs{
				ContainerID: "dummy",
				Netns:       targetNS.Path(),
				IfName:      IFNAME,
				StdinData:   conf,
			}

			beforeConf = configToRestore{}

			err := originalNS.Do(func(ns.NetNS) error {
				defer GinkgoRecover()

				r, _, err := testutils.CmdAddWithArgs(args, func() error {
					return cmdAdd(args)
				})
				Expect(err).NotTo(HaveOccurred())

				result, err := types100.GetResult(r)
				Expect(err).NotTo(HaveOccurred())

				Expect(result.Interfaces).To(HaveLen(1))
				Expect(result.Interfaces[0].Name).To(Equal(IFNAME))
				Expect(result.IPs).To(HaveLen(1))
				Expect(result.IPs[0].Address.String()).To(Equal("10.0.0.2/24"))

				Expect("/tmp/tuning-test/dummy_dummy0.json").ShouldNot(BeAnExistingFile())

				err = testutils.CmdDel(originalNS.Path(),
					args.ContainerID, "", func() error { return cmdDel(args) })
				Expect(err).NotTo(HaveOccurred())

				return nil
			})
			Expect(err).NotTo(HaveOccurred())
		})

		It(fmt.Sprintf("[%s] configures and deconfigures promiscuous mode with ADD/DEL", ver), func() {
			conf := []byte(fmt.Sprintf(`{
				"name": "test",
				"type": "iplink",
				"cniVersion": "%s",
				"promisc": true,
				"prevResult": {
					"interfaces": [
						{"name": "dummy0", "sandbox":"netns"}
					],
					"ips": [
						{
							"version": "4",
							"address": "10.0.0.2/24",
							"gateway": "10.0.0.1",
							"interface": 0
						}
					]
				}
			}`, ver))

			args := &skel.CmdArgs{
				ContainerID: "dummy",
				Netns:       originalNS.Path(),
				IfName:      IFNAME,
				StdinData:   conf,
			}

			err := originalNS.Do(func(ns.NetNS) error {
				defer GinkgoRecover()

				r, _, err := testutils.CmdAddWithArgs(args, func() error {
					return cmdAdd(args)
				})
				Expect(err).NotTo(HaveOccurred())

				result, err := types100.GetResult(r)
				Expect(err).NotTo(HaveOccurred())

				Expect(result.Interfaces).To(HaveLen(1))
				Expect(result.Interfaces[0].Name).To(Equal(IFNAME))
				Expect(result.IPs).To(HaveLen(1))
				Expect(result.IPs[0].Address.String()).To(Equal("10.0.0.2/24"))

				link, err := netlink.LinkByName(IFNAME)
				Expect(err).NotTo(HaveOccurred())
				Expect(link.Attrs().Promisc).To(Equal(1))

				if testutils.SpecVersionHasCHECK(ver) {
					n := &TuningConf{}
					err = json.Unmarshal(conf, &n)
					Expect(err).NotTo(HaveOccurred())

					confString, err := buildOneConfig(ver, n, r)
					Expect(err).NotTo(HaveOccurred())

					args.StdinData = confString

					err = testutils.CmdCheckWithArgs(args, func() error {
						return cmdCheck(args)
					})
					Expect(err).NotTo(HaveOccurred())
				}

				err = testutils.CmdDel(originalNS.Path(),
					args.ContainerID, "", func() error { return cmdDel(args) })
				Expect(err).NotTo(HaveOccurred())

				link, err = netlink.LinkByName(IFNAME)
				Expect(err).NotTo(HaveOccurred())
				Expect(link.Attrs().Promisc != 0).To(Equal(*beforeConf.Promisc))

				return nil
			})
			Expect(err).NotTo(HaveOccurred())
		})

		It(fmt.Sprintf("[%s] configures and deconfigures promiscuous mode from args with ADD/DEL", ver), func() {
			conf := []byte(fmt.Sprintf(`{
				"name": "test",
				"type": "iplink",
				"cniVersion": "%s",
				"args": {
				    "cni": {
					"promisc": true
				    }
				},
				"prevResult": {
					"interfaces": [
						{"name": "dummy0", "sandbox":"netns"}
					],
					"ips": [
						{
							"version": "4",
							"address": "10.0.0.2/24",
							"gateway": "10.0.0.1",
							"interface": 0
						}
					]
				}
			}`, ver))

			args := &skel.CmdArgs{
				ContainerID: "dummy",
				Netns:       originalNS.Path(),
				IfName:      IFNAME,
				StdinData:   conf,
			}

			err := originalNS.Do(func(ns.NetNS) error {
				defer GinkgoRecover()

				r, _, err := testutils.CmdAddWithArgs(args, func() error {
					return cmdAdd(args)
				})
				Expect(err).NotTo(HaveOccurred())

				result, err := types100.GetResult(r)
				Expect(err).NotTo(HaveOccurred())

				Expect(result.Interfaces).To(HaveLen(1))
				Expect(result.Interfaces[0].Name).To(Equal(IFNAME))
				Expect(result.IPs).To(HaveLen(1))
				Expect(result.IPs[0].Address.String()).To(Equal("10.0.0.2/24"))

				link, err := netlink.LinkByName(IFNAME)
				Expect(err).NotTo(HaveOccurred())
				Expect(link.Attrs().Promisc).To(Equal(1))

				err = testutils.CmdDel(originalNS.Path(),
					args.ContainerID, "", func() error { return cmdDel(args) })
				Expect(err).NotTo(HaveOccurred())

				link, err = netlink.LinkByName(IFNAME)
				Expect(err).NotTo(HaveOccurred())
				Expect(link.Attrs().Promisc != 0).To(Equal(*beforeConf.Promisc))

				return nil
			})
			Expect(err).NotTo(HaveOccurred())
		})

		It(fmt.Sprintf("[%s] configures and deconfigures mtu with ADD/DEL", ver), func() {
			conf := []byte(fmt.Sprintf(`{
				"name": "test",
				"type": "iplink",
				"cniVersion": "%s",
				"mtu": 1454,
				"prevResult": {
					"interfaces": [
						{"name": "dummy0", "sandbox":"netns"}
					],
					"ips": [
						{
							"version": "4",
							"address": "10.0.0.2/24",
							"gateway": "10.0.0.1",
							"interface": 0
						}
					]
				}
			}`, ver))

			args := &skel.CmdArgs{
				ContainerID: "dummy",
				Netns:       originalNS.Path(),
				IfName:      IFNAME,
				StdinData:   conf,
			}

			err := originalNS.Do(func(ns.NetNS) error {
				defer GinkgoRecover()

				r, _, err := testutils.CmdAddWithArgs(args, func() error {
					return cmdAdd(args)
				})
				Expect(err).NotTo(HaveOccurred())

				result, err := types100.GetResult(r)
				Expect(err).NotTo(HaveOccurred())

				Expect(result.Interfaces).To(HaveLen(1))
				Expect(result.Interfaces[0].Name).To(Equal(IFNAME))
				Expect(result.IPs).To(HaveLen(1))
				Expect(result.IPs[0].Address.String()).To(Equal("10.0.0.2/24"))

				link, err := netlink.LinkByName(IFNAME)
				Expect(err).NotTo(HaveOccurred())
				Expect(link.Attrs().MTU).To(Equal(1454))

				if testutils.SpecVersionHasCHECK(ver) {
					n := &TuningConf{}
					err = json.Unmarshal(conf, &n)
					Expect(err).NotTo(HaveOccurred())

					confString, err := buildOneConfig(ver, n, r)
					Expect(err).NotTo(HaveOccurred())

					args.StdinData = confString

					err = testutils.CmdCheckWithArgs(args, func() error {
						return cmdCheck(args)
					})
					Expect(err).NotTo(HaveOccurred())
				}

				err = testutils.CmdDel(originalNS.Path(),
					args.ContainerID, "", func() error { return cmdDel(args) })
				Expect(err).NotTo(HaveOccurred())

				link, err = netlink.LinkByName(IFNAME)
				Expect(err).NotTo(HaveOccurred())
				Expect(link.Attrs().MTU).To(Equal(beforeConf.Mtu))

				return nil
			})
			Expect(err).NotTo(HaveOccurred())
		})

		It(fmt.Sprintf("[%s] configures and deconfigures mtu from args with ADD/DEL", ver), func() {
			conf := []byte(fmt.Sprintf(`{
				"name": "test",
				"type": "iplink",
				"cniVersion": "%s",
				"args": {
				    "cni": {
					"mtu": 1454
				    }
				},
				"prevResult": {
					"interfaces": [
						{"name": "dummy0", "sandbox":"netns"}
					],
					"ips": [
						{
							"version": "4",
							"address": "10.0.0.2/24",
							"gateway": "10.0.0.1",
							"interface": 0
						}
					]
				}
			}`, ver))

			args := &skel.CmdArgs{
				ContainerID: "dummy",
				Netns:       originalNS.Path(),
				IfName:      IFNAME,
				StdinData:   conf,
			}

			err := originalNS.Do(func(ns.NetNS) error {
				defer GinkgoRecover()

				r, _, err := testutils.CmdAddWithArgs(args, func() error {
					return cmdAdd(args)
				})
				Expect(err).NotTo(HaveOccurred())

				result, err := types100.GetResult(r)
				Expect(err).NotTo(HaveOccurred())

				Expect(result.Interfaces).To(HaveLen(1))
				Expect(result.Interfaces[0].Name).To(Equal(IFNAME))
				Expect(result.IPs).To(HaveLen(1))
				Expect(result.IPs[0].Address.String()).To(Equal("10.0.0.2/24"))

				link, err := netlink.LinkByName(IFNAME)
				Expect(err).NotTo(HaveOccurred())
				Expect(link.Attrs().MTU).To(Equal(1454))

				err = testutils.CmdDel(originalNS.Path(),
					args.ContainerID, "", func() error { return cmdDel(args) })
				Expect(err).NotTo(HaveOccurred())

				link, err = netlink.LinkByName(IFNAME)
				Expect(err).NotTo(HaveOccurred())
				Expect(link.Attrs().MTU).To(Equal(beforeConf.Mtu))

				return nil
			})
			Expect(err).NotTo(HaveOccurred())
		})

		It(fmt.Sprintf("[%s] configures and deconfigures tx queue len with ADD/DEL", ver), func() {
			conf := []byte(fmt.Sprintf(`{
				"name": "test",
				"type": "iplink",
				"cniVersion": "%s",
				"txQLen": 20000,
				"prevResult": {
					"interfaces": [
						{"name": "dummy0", "sandbox":"netns"}
					],
					"ips": [
						{
							"version": "4",
							"address": "10.0.0.2/24",
							"gateway": "10.0.0.1",
							"interface": 0
						}
					]
				}
			}`, ver))

			args := &skel.CmdArgs{
				ContainerID: "dummy",
				Netns:       originalNS.Path(),
				IfName:      IFNAME,
				StdinData:   conf,
			}

			err := originalNS.Do(func(ns.NetNS) error {
				defer GinkgoRecover()

				r, _, err := testutils.CmdAddWithArgs(args, func() error {
					return cmdAdd(args)
				})
				Expect(err).NotTo(HaveOccurred())

				link, err := netlink.LinkByName(IFNAME)
				Expect(err).NotTo(HaveOccurred())
				Expect(link.Attrs().TxQLen).To(Equal(20000))

				if testutils.SpecVersionHasCHECK(ver) {
					n := &TuningConf{}
					Expect(json.Unmarshal(conf, &n)).NotTo(HaveOccurred())

					confString, err := buildOneConfig(ver, n, r)
					Expect(err).NotTo(HaveOccurred())

					args.StdinData = confString

					Expect(testutils.CmdCheckWithArgs(args, func() error {
						return cmdCheck(args)
					})).NotTo(HaveOccurred())
				}

				err = testutils.CmdDel(originalNS.Path(),
					args.ContainerID, "", func() error { return cmdDel(args) })
				Expect(err).NotTo(HaveOccurred())

				link, err = netlink.LinkByName(IFNAME)
				Expect(err).NotTo(HaveOccurred())
				Expect(link.Attrs().TxQLen).To(Equal(*beforeConf.TxQLen))

				return nil
			})
			Expect(err).NotTo(HaveOccurred())
		})

		It(fmt.Sprintf("[%s] configures and deconfigures tx queue len from args with ADD/DEL", ver), func() {
			conf := []byte(fmt.Sprintf(`{
				"name": "test",
				"type": "iplink",
				"cniVersion": "%s",
				"args": {
				    "cni": {
					"txQLen": 20000
				    }
				},
				"prevResult": {
					"interfaces": [
						{"name": "dummy0", "sandbox":"netns"}
					],
					"ips": [
						{
							"version": "4",
							"address": "10.0.0.2/24",
							"gateway": "10.0.0.1",
							"interface": 0
						}
					]
				}
			}`, ver))

			args := &skel.CmdArgs{
				ContainerID: "dummy",
				Netns:       originalNS.Path(),
				IfName:      IFNAME,
				StdinData:   conf,
			}

			err := originalNS.Do(func(ns.NetNS) error {
				defer GinkgoRecover()

				r, _, err := testutils.CmdAddWithArgs(args, func() error {
					return cmdAdd(args)
				})
				Expect(err).NotTo(HaveOccurred())

				result, err := types100.GetResult(r)
				Expect(err).NotTo(HaveOccurred())

				Expect(result.Interfaces).To(HaveLen(1))
				Expect(result.Interfaces[0].Name).To(Equal(IFNAME))
				Expect(result.IPs).To(HaveLen(1))
				Expect(result.IPs[0].Address.String()).To(Equal("10.0.0.2/24"))

				link, err := netlink.LinkByName(IFNAME)
				Expect(err).NotTo(HaveOccurred())
				Expect(link.Attrs().TxQLen).To(Equal(20000))

				err = testutils.CmdDel(originalNS.Path(),
					args.ContainerID, "", func() error { return cmdDel(args) })
				Expect(err).NotTo(HaveOccurred())

				link, err = netlink.LinkByName(IFNAME)
				Expect(err).NotTo(HaveOccurred())
				Expect(link.Attrs().TxQLen).To(Equal(*beforeConf.TxQLen))

				return nil
			})
			Expect(err).NotTo(HaveOccurred())
		})

		It(fmt.Sprintf("[%s] configures and deconfigures mac address (from conf file) with ADD/DEL", ver), func() {
			mac := "c2:11:22:33:44:55"
			conf := []byte(fmt.Sprintf(`{
				"name": "test",
				"type": "iplink",
				"cniVersion": "%s",
				"mac": "%s",
				"prevResult": {
					"interfaces": [
						{"name": "dummy0", "sandbox":"netns"}
					],
					"ips": [
						{
							"version": "4",
							"address": "10.0.0.2/24",
							"gateway": "10.0.0.1",
							"interface": 0
						}
					]
				}
			}`, ver, mac))

			args := &skel.CmdArgs{
				ContainerID: "dummy",
				Netns:       originalNS.Path(),
				IfName:      IFNAME,
				StdinData:   conf,
			}

			err := originalNS.Do(func(ns.NetNS) error {
				defer GinkgoRecover()

				r, _, err := testutils.CmdAddWithArgs(args, func() error {
					return cmdAdd(args)
				})
				Expect(err).NotTo(HaveOccurred())

				result, err := types100.GetResult(r)
				Expect(err).NotTo(HaveOccurred())

				Expect(result.Interfaces).To(HaveLen(1))
				Expect(result.Interfaces[0].Name).To(Equal(IFNAME))
				Expect(result.IPs).To(HaveLen(1))
				Expect(result.IPs[0].Address.String()).To(Equal("10.0.0.2/24"))

				Expect(result.Interfaces[0].Mac).To(Equal(mac))
				link, err := netlink.LinkByName(IFNAME)
				Expect(err).NotTo(HaveOccurred())
				hw, err := net.ParseMAC(mac)
				Expect(err).NotTo(HaveOccurred())
				Expect(link.Attrs().HardwareAddr).To(Equal(hw))

				if testutils.SpecVersionHasCHECK(ver) {
					n := &TuningConf{}
					err = json.Unmarshal(conf, &n)
					Expect(err).NotTo(HaveOccurred())

					confString, err := buildOneConfig(ver, n, r)
					Expect(err).NotTo(HaveOccurred())

					args.StdinData = confString

					err = testutils.CmdCheckWithArgs(args, func() error {
						return cmdCheck(args)
					})
					Expect(err).NotTo(HaveOccurred())
				}

				err = testutils.CmdDel(originalNS.Path(),
					args.ContainerID, "", func() error { return cmdDel(args) })
				Expect(err).NotTo(HaveOccurred())

				link, err = netlink.LinkByName(IFNAME)
				Expect(err).NotTo(HaveOccurred())
				Expect(link.Attrs().HardwareAddr.String()).To(Equal(beforeConf.Mac))

				return nil
			})
			Expect(err).NotTo(HaveOccurred())
		})

		It(fmt.Sprintf("[%s] configures and deconfigures mac address (from args) with ADD/DEL", ver), func() {
			conf := []byte(fmt.Sprintf(`{
				"name": "test",
				"type": "iplink",
				"cniVersion": "%s",
				"args": {
				    "cni": {
					"mac": "c2:11:22:33:44:55"
				    }
				},
				"prevResult": {
					"interfaces": [
						{"name": "dummy0", "sandbox":"netns"}
					],
					"ips": [
						{
							"version": "4",
							"address": "10.0.0.2/24",
							"gateway": "10.0.0.1",
							"interface": 0
						}
					]
				}
			}`, ver))

			args := &skel.CmdArgs{
				ContainerID: "dummy",
				Netns:       originalNS.Path(),
				IfName:      IFNAME,
				StdinData:   conf,
			}

			err := originalNS.Do(func(ns.NetNS) error {
				defer GinkgoRecover()

				r, _, err := testutils.CmdAddWithArgs(args, func() error {
					return cmdAdd(args)
				})
				Expect(err).NotTo(HaveOccurred())

				result, err := types100.GetResult(r)
				Expect(err).NotTo(HaveOccurred())

				Expect(result.Interfaces).To(HaveLen(1))
				Expect(result.Interfaces[0].Name).To(Equal(IFNAME))
				Expect(result.IPs).To(HaveLen(1))
				Expect(result.IPs[0].Address.String()).To(Equal("10.0.0.2/24"))

				link, err := netlink.LinkByName(IFNAME)
				Expect(err).NotTo(HaveOccurred())
				hw, err := net.ParseMAC("c2:11:22:33:44:55")
				Expect(err).NotTo(HaveOccurred())
				Expect(link.Attrs().HardwareAddr).To(Equal(hw))

				err = testutils.CmdDel(originalNS.Path(),
					args.ContainerID, "", func() error { return cmdDel(args) })
				Expect(err).NotTo(HaveOccurred())

				link, err = netlink.LinkByName(IFNAME)
				Expect(err).NotTo(HaveOccurred())
				Expect(link.Attrs().HardwareAddr.String()).To(Equal(beforeConf.Mac))

				return nil
			})
			Expect(err).NotTo(HaveOccurred())
		})

		It(fmt.Sprintf("[%s] configures and deconfigures mac address (from CNI_ARGS) with ADD/DEL", ver), func() {
			conf := []byte(fmt.Sprintf(`{
				"name": "test",
				"type": "iplink",
				"cniVersion": "%s",
				"prevResult": {
					"interfaces": [
						{"name": "dummy0", "sandbox":"netns"}
					],
					"ips": [
						{
							"version": "4",
							"address": "10.0.0.2/24",
							"gateway": "10.0.0.1",
							"interface": 0
						}
					]
				}
			}`, ver))

			args := &skel.CmdArgs{
				ContainerID: "dummy",
				Netns:       originalNS.Path(),
				IfName:      IFNAME,
				StdinData:   conf,
				Args:        "IgnoreUnknown=true;MAC=c2:11:22:33:44:66",
			}

			err := originalNS.Do(func(ns.NetNS) error {
				defer GinkgoRecover()

				r, _, err := testutils.CmdAddWithArgs(args, func() error {
					return cmdAdd(args)
				})
				Expect(err).NotTo(HaveOccurred())

				result, err := types100.GetResult(r)
				Expect(err).NotTo(HaveOccurred())

				Expect(result.Interfaces).To(HaveLen(1))
				Expect(result.Interfaces[0].Name).To(Equal(IFNAME))
				Expect(result.IPs).To(HaveLen(1))
				Expect(result.IPs[0].Address.String()).To(Equal("10.0.0.2/24"))

				link, err := netlink.LinkByName(IFNAME)
				Expect(err).NotTo(HaveOccurred())
				hw, err := net.ParseMAC("c2:11:22:33:44:66")
				Expect(err).NotTo(HaveOccurred())
				Expect(link.Attrs().HardwareAddr).To(Equal(hw))

				if testutils.SpecVersionHasCHECK(ver) {
					n := &TuningConf{}
					err = json.Unmarshal(conf, &n)
					Expect(err).NotTo(HaveOccurred())

					confString, err := buildOneConfig(ver, n, r)
					Expect(err).NotTo(HaveOccurred())

					args.StdinData = confString

					err = testutils.CmdCheckWithArgs(args, func() error {
						return cmdCheck(args)
					})
					Expect(err).NotTo(HaveOccurred())
				}

				err = testutils.CmdDel(originalNS.Path(),
					args.ContainerID, "", func() error { return cmdDel(args) })
				Expect(err).NotTo(HaveOccurred())

				link, err = netlink.LinkByName(IFNAME)
				Expect(err).NotTo(HaveOccurred())
				Expect(link.Attrs().HardwareAddr.String()).To(Equal(beforeConf.Mac))

				return nil
			})
			Expect(err).NotTo(HaveOccurred())
		})

		It(fmt.Sprintf("[%s] configures and deconfigures mac address (from RuntimeConfig) with ADD/DEL", ver), func() {
			conf := []byte(fmt.Sprintf(`{
				"name": "test",
				"type": "iplink",
				"cniVersion": "%s",
				"capabilities": {"mac": true},
				"RuntimeConfig": {
				    "mac": "c2:11:22:33:44:55"
				},
				"prevResult": {
					"interfaces": [
						{"name": "dummy0", "sandbox":"netns"}
					],
					"ips": [
						{
							"version": "4",
							"address": "10.0.0.2/24",
							"gateway": "10.0.0.1",
							"interface": 0
						}
					]
				}
			}`, ver))

			args := &skel.CmdArgs{
				ContainerID: "dummy",
				Netns:       originalNS.Path(),
				IfName:      IFNAME,
				StdinData:   conf,
			}

			err := originalNS.Do(func(ns.NetNS) error {
				defer GinkgoRecover()

				r, _, err := testutils.CmdAddWithArgs(args, func() error {
					return cmdAdd(args)
				})
				Expect(err).NotTo(HaveOccurred())

				result, err := types100.GetResult(r)
				Expect(err).NotTo(HaveOccurred())

				Expect(result.Interfaces).To(HaveLen(1))
				Expect(result.Interfaces[0].Name).To(Equal(IFNAME))
				Expect(result.IPs).To(HaveLen(1))
				Expect(result.IPs[0].Address.String()).To(Equal("10.0.0.2/24"))

				link, err := netlink.LinkByName(IFNAME)
				Expect(err).NotTo(HaveOccurred())
				hw, err := net.ParseMAC("c2:11:22:33:44:55")
				Expect(err).NotTo(HaveOccurred())
				Expect(link.Attrs().HardwareAddr).To(Equal(hw))

				err = testutils.CmdDel(originalNS.Path(),
					args.ContainerID, "", func() error { return cmdDel(args) })
				Expect(err).NotTo(HaveOccurred())

				link, err = netlink.LinkByName(IFNAME)
				Expect(err).NotTo(HaveOccurred())
				Expect(link.Attrs().HardwareAddr.String()).To(Equal(beforeConf.Mac))

				return nil
			})
			Expect(err).NotTo(HaveOccurred())
		})

		It(fmt.Sprintf("[%s] configures and deconfigures mac address, promisc mode, MTU and tx queue len (from conf file) with custom dataDir", ver), func() {
			conf := []byte(fmt.Sprintf(`{
				"name": "test",
				"type": "iplink",
				"cniVersion": "%s",
				"mac": "c2:11:22:33:44:77",
				"promisc": true,
				"mtu": 4000,
				"txQLen": 20000,
				"dataDir": "/tmp/tuning-test",
				"prevResult": {
					"interfaces": [
						{"name": "dummy0", "sandbox":"netns"}
					],
					"ips": [
						{
							"version": "4",
							"address": "10.0.0.2/24",
							"gateway": "10.0.0.1",
							"interface": 0
						}
					]
				}
			}`, ver))

			args := &skel.CmdArgs{
				ContainerID: "dummy",
				Netns:       originalNS.Path(),
				IfName:      IFNAME,
				StdinData:   conf,
			}

			err := originalNS.Do(func(ns.NetNS) error {
				defer GinkgoRecover()

				r, _, err := testutils.CmdAddWithArgs(args, func() error {
					return cmdAdd(args)
				})
				Expect(err).NotTo(HaveOccurred())

				result, err := types100.GetResult(r)
				Expect(err).NotTo(HaveOccurred())

				Expect(result.Interfaces).To(HaveLen(1))
				Expect(result.Interfaces[0].Name).To(Equal(IFNAME))
				Expect(result.IPs).To(HaveLen(1))
				Expect(result.IPs[0].Address.String()).To(Equal("10.0.0.2/24"))

				link, err := netlink.LinkByName(IFNAME)
				Expect(err).NotTo(HaveOccurred())
				hw, err := net.ParseMAC("c2:11:22:33:44:77")
				Expect(err).NotTo(HaveOccurred())
				Expect(link.Attrs().HardwareAddr).To(Equal(hw))
				Expect(link.Attrs().Promisc).To(Equal(1))
				Expect(link.Attrs().MTU).To(Equal(4000))
				Expect(link.Attrs().TxQLen).To(Equal(20000))

				Expect("/tmp/tuning-test/dummy_dummy0.json").Should(BeAnExistingFile())

				if testutils.SpecVersionHasCHECK(ver) {
					n := &TuningConf{}
					err = json.Unmarshal(conf, &n)
					Expect(err).NotTo(HaveOccurred())

					confString, err := buildOneConfig(ver, n, r)
					Expect(err).NotTo(HaveOccurred())

					args.StdinData = confString

					err = testutils.CmdCheckWithArgs(args, func() error {
						return cmdCheck(args)
					})
					Expect(err).NotTo(HaveOccurred())
				}

				err = testutils.CmdDel(originalNS.Path(),
					args.ContainerID, "", func() error { return cmdDel(args) })
				Expect(err).NotTo(HaveOccurred())

				link, err = netlink.LinkByName(IFNAME)
				Expect(err).NotTo(HaveOccurred())
				Expect(link.Attrs().HardwareAddr.String()).To(Equal(beforeConf.Mac))
				Expect(link.Attrs().MTU).To(Equal(beforeConf.Mtu))
				Expect(link.Attrs().Promisc != 0).To(Equal(*beforeConf.Promisc))
				Expect(link.Attrs().TxQLen).To(Equal(*beforeConf.TxQLen))

				return nil
			})
			Expect(err).NotTo(HaveOccurred())
		})

		It(fmt.Sprintf("[%s] configures and deconfigures all-multicast mode with ADD/DEL", ver), func() {
			conf := []byte(fmt.Sprintf(`{
				"name": "test",
				"type": "iplink",
				"cniVersion": "%s",
				"allmulti": true,
				"prevResult": {
					"interfaces": [
						{"name": "dummy0", "sandbox":"netns"}
					],
					"ips": [
						{
							"version": "4",
							"address": "10.0.0.2/24",
							"gateway": "10.0.0.1",
							"interface": 0
						}
					]
				}
			}`, ver))

			args := &skel.CmdArgs{
				ContainerID: "dummy",
				Netns:       originalNS.Path(),
				IfName:      IFNAME,
				StdinData:   conf,
			}

			err := originalNS.Do(func(ns.NetNS) error {
				defer GinkgoRecover()

				r, _, err := testutils.CmdAddWithArgs(args, func() error {
					return cmdAdd(args)
				})
				Expect(err).NotTo(HaveOccurred())

				result, err := types100.GetResult(r)
				Expect(err).NotTo(HaveOccurred())

				Expect(result.Interfaces).To(HaveLen(1))
				Expect(result.Interfaces[0].Name).To(Equal(IFNAME))
				Expect(result.IPs).To(HaveLen(1))
				Expect(result.IPs[0].Address.String()).To(Equal("10.0.0.2/24"))

				link, err := netlink.LinkByName(IFNAME)
				Expect(err).NotTo(HaveOccurred())
				Expect(link.Attrs().RawFlags & unix.IFF_ALLMULTI).NotTo(BeZero())

				if testutils.SpecVersionHasCHECK(ver) {
					n := &TuningConf{}
					err = json.Unmarshal(conf, &n)
					Expect(err).NotTo(HaveOccurred())

					confString, err := buildOneConfig(ver, n, r)
					Expect(err).NotTo(HaveOccurred())

					args.StdinData = confString

					err = testutils.CmdCheckWithArgs(args, func() error {
						return cmdCheck(args)
					})
					Expect(err).NotTo(HaveOccurred())
				}

				err = testutils.CmdDel(originalNS.Path(),
					args.ContainerID, "", func() error { return cmdDel(args) })
				Expect(err).NotTo(HaveOccurred())

				link, err = netlink.LinkByName(IFNAME)
				Expect(err).NotTo(HaveOccurred())
				Expect(link.Attrs().RawFlags&unix.IFF_ALLMULTI != 0).To(Equal(*beforeConf.Allmulti))

				return nil
			})
			Expect(err).NotTo(HaveOccurred())
		})

		It(fmt.Sprintf("[%s] configures and deconfigures all-multicast mode from args with ADD/DEL", ver), func() {
			conf := []byte(fmt.Sprintf(`{
				"name": "test",
				"type": "iplink",
				"cniVersion": "%s",
				"args": {
				    "cni": {
					"allmulti": true
				    }
				},
				"prevResult": {
					"interfaces": [
						{"name": "dummy0", "sandbox":"netns"}
					],
					"ips": [
						{
							"version": "4",
							"address": "10.0.0.2/24",
							"gateway": "10.0.0.1",
							"interface": 0
						}
					]
				}
			}`, ver))

			args := &skel.CmdArgs{
				ContainerID: "dummy",
				Netns:       originalNS.Path(),
				IfName:      IFNAME,
				StdinData:   conf,
			}

			err := originalNS.Do(func(ns.NetNS) error {
				defer GinkgoRecover()

				r, _, err := testutils.CmdAddWithArgs(args, func() error {
					return cmdAdd(args)
				})
				Expect(err).NotTo(HaveOccurred())

				result, err := types100.GetResult(r)
				Expect(err).NotTo(HaveOccurred())

				Expect(result.Interfaces).To(HaveLen(1))
				Expect(result.Interfaces[0].Name).To(Equal(IFNAME))
				Expect(result.IPs).To(HaveLen(1))
				Expect(result.IPs[0].Address.String()).To(Equal("10.0.0.2/24"))

				link, err := netlink.LinkByName(IFNAME)
				Expect(err).NotTo(HaveOccurred())
				Expect(link.Attrs().RawFlags & unix.IFF_ALLMULTI).NotTo(BeZero())

				err = testutils.CmdDel(originalNS.Path(),
					args.ContainerID, "", func() error { return cmdDel(args) })
				Expect(err).NotTo(HaveOccurred())

				link, err = netlink.LinkByName(IFNAME)
				Expect(err).NotTo(HaveOccurred())
				Expect(link.Attrs().RawFlags&unix.IFF_ALLMULTI != 0).To(Equal(*beforeConf.Allmulti))

				return nil
			})
			Expect(err).NotTo(HaveOccurred())
		})

		It(fmt.Sprintf("[%s] passes prevResult through unchanged", ver), func() {
			conf := []byte(fmt.Sprintf(`{
				"name": "test",
				"type": "tuning",
				"cniVersion": "%s",
				"sysctl": {
					"net.ipv4.conf.all.log_martians": "1"
				},
				"prevResult": {
					"interfaces": [
						{"name": "dummy0", "sandbox":"netns"}
					],
					"ips": [
						{
							"version": "4",
							"address": "10.0.0.2/24",
							"gateway": "10.0.0.1",
							"interface": 0
						}
					]
				}
			}`, ver))

			args := &skel.CmdArgs{
				ContainerID: "dummy",
				Netns:       targetNS.Path(),
				IfName:      IFNAME,
				StdinData:   conf,
			}

			beforeConf = configToRestore{}

			err := createSysctlAllowFile([]string{"^net\\.ipv4\\.conf\\.other\\.[a-z_]*$"})
			Expect(err).NotTo(HaveOccurred())

			err = originalNS.Do(func(ns.NetNS) error {
				defer GinkgoRecover()

				_, _, err := testutils.CmdAddWithArgs(args, func() error {
					return cmdAdd(args)
				})
				Expect(err).To(HaveOccurred())

				err = testutils.CmdDel(originalNS.Path(),
					args.ContainerID, "", func() error { return cmdDel(args) })
				Expect(err).NotTo(HaveOccurred())

				return nil
			})
			Expect(err).NotTo(HaveOccurred())
		})

		It(fmt.Sprintf("[%s] passes prevResult through unchanged", ver), func() {
			conf := []byte(fmt.Sprintf(`{
				"name": "test",
				"type": "tuning",
				"cniVersion": "%s",
				"sysctl": {
					"net.ipv4.conf.all.log_martians": "1"
				},
				"prevResult": {
					"interfaces": [
						{"name": "dummy0", "sandbox":"netns"}
					],
					"ips": [
						{
							"version": "4",
							"address": "10.0.0.2/24",
							"gateway": "10.0.0.1",
							"interface": 0
						}
					]
				}
			}`, ver))

			args := &skel.CmdArgs{
				ContainerID: "dummy",
				Netns:       targetNS.Path(),
				IfName:      IFNAME,
				StdinData:   conf,
			}

			err := createSysctlAllowFile([]string{"^net\\.ipv4\\.conf\\.all\\.[a-z_]*$"})
			Expect(err).NotTo(HaveOccurred())

			beforeConf = configToRestore{}

			err = originalNS.Do(func(ns.NetNS) error {
				defer GinkgoRecover()

				r, _, err := testutils.CmdAddWithArgs(args, func() error {
					return cmdAdd(args)
				})
				Expect(err).NotTo(HaveOccurred())

				result, err := types100.GetResult(r)
				Expect(err).NotTo(HaveOccurred())

				Expect(result.Interfaces).To(HaveLen(1))
				Expect(result.Interfaces[0].Name).To(Equal(IFNAME))
				Expect(result.IPs).To(HaveLen(1))
				Expect(result.IPs[0].Address.String()).To(Equal("10.0.0.2/24"))

				err = testutils.CmdDel(originalNS.Path(),
					args.ContainerID, "", func() error { return cmdDel(args) })
				Expect(err).NotTo(HaveOccurred())

				return nil
			})
			Expect(err).NotTo(HaveOccurred())
		})

		It(fmt.Sprintf("[%s] does not allow duplicated sysctl values", ver), func() {
			conf := []byte(fmt.Sprintf(`{
				"name": "test",
				"type": "tuning",
				"cniVersion": "%s",
				"sysctl": {
					"net.ipv4.conf.all.log_martians": "1",
					"net.ipv4.conf.all.log_martians": "0"
				},
				"prevResult": {
					"interfaces": [
						{"name": "dummy0", "sandbox":"netns"}
					],
					"ips": [
						{
							"version": "4",
							"address": "10.0.0.2/24",
							"gateway": "10.0.0.1",
							"interface": 0
						}
					]
				}
			}`, ver))

			args := &skel.CmdArgs{
				ContainerID: "dummy",
				Netns:       targetNS.Path(),
				IfName:      IFNAME,
				StdinData:   conf,
			}

			beforeConf = configToRestore{}

			err := originalNS.Do(func(ns.NetNS) error {
				defer GinkgoRecover()

				_, _, err := testutils.CmdAddWithArgs(args, func() error {
					return cmdAdd(args)
				})
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("duplicated"))

				return nil
			})
			Expect(err).NotTo(HaveOccurred())
		})

		It(fmt.Sprintf("[%s] does not allow ifname with path separator", ver), func() {
			conf := []byte(fmt.Sprintf(`{
				"name": "test",
				"type": "tuning",
				"cniVersion": "%s",
				"sysctl": {
					"net.ipv4.conf.all.log_martians": "1"
				},
				"prevResult": {
					"interfaces": [
						{"name": "eth/0", "sandbox":"netns"}
					],
					"ips": [
						{
							"version": "4",
							"address": "10.0.0.2/24",
							"gateway": "10.0.0.1",
							"interface": 0
						}
					]
				}
			}`, ver))

			args := &skel.CmdArgs{
				ContainerID: "dummy",
				Netns:       targetNS.Path(),
				IfName:      "eth/0",
				StdinData:   conf,
			}

			beforeConf = configToRestore{}

			err := originalNS.Do(func(ns.NetNS) error {
				defer GinkgoRecover()

				_, _, err := testutils.CmdAddWithArgs(args, func() error {
					return cmdAdd(args)
				})
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("invalid character"))

				return nil
			})
			Expect(err).NotTo(HaveOccurred())
		})

	}
})
