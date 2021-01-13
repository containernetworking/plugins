// Copyright 2015 CNI authors
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
	"io/ioutil"
	"os"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types/current"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/containernetworking/plugins/pkg/testutils"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Flannel", func() {
	var (
		originalNS          ns.NetNS
		onlyIpv4Input       string
		onlyIpv6Input       string
		dualStackInput      string
		onlyIpv4SubnetFile  string
		onlyIpv6SubnetFile  string
		dualStackSubnetFile string
		dataDir             string
	)

	BeforeEach(func() {
		var err error
		originalNS, err = testutils.NewNS()
		Expect(err).NotTo(HaveOccurred())
	})

	AfterEach(func() {
		Expect(originalNS.Close()).To(Succeed())
	})

	const inputTemplate = `
{
    "name": "cni-flannel",
    "type": "flannel",
    "subnetFile": "%s",
    "dataDir": "%s"%s
}`

	const inputIPAMTemplate = `
    "unknown-param": "unknown-value",
    "routes": [%s]%s`

	const inputIPAMType = "my-ipam"

	const inputIPAMNoTypeTemplate = `
{
    "unknown-param": "unknown-value",
    "routes": [%s]%s
}`

	const inputIPAMRoutes = `
      { "dst": "10.96.0.0/12" },
      { "dst": "192.168.244.0/24", "gw": "10.1.17.20" }`

	const onlyIpv4FlannelSubnetEnv = `
FLANNEL_NETWORK=10.1.0.0/16
FLANNEL_SUBNET=10.1.17.1/24
FLANNEL_MTU=1472
FLANNEL_IPMASQ=true
`
	const onlyIpv6FlannelSubnetEnv = `
FLANNEL_IPV6_NETWORK=fc00::/48
FLANNEL_IPV6_SUBNET=fc00::1/64
FLANNEL_MTU=1472
FLANNEL_IPMASQ=true
`
	const dualStackFlannelSubnetEnv = `
FLANNEL_NETWORK=10.1.0.0/16
FLANNEL_SUBNET=10.1.17.1/24
FLANNEL_IPV6_NETWORK=fc00::/48
FLANNEL_IPV6_SUBNET=fc00::1/64
FLANNEL_MTU=1472
FLANNEL_IPMASQ=true
`

	var writeSubnetEnv = func(contents string) string {
		file, err := ioutil.TempFile("", "subnet.env")
		Expect(err).NotTo(HaveOccurred())
		_, err = file.WriteString(contents)
		Expect(err).NotTo(HaveOccurred())
		return file.Name()
	}

	var makeInputIPAM = func(ipamType, routes, extra string) string {
		c := "{\n"
		if len(ipamType) > 0 {
			c += fmt.Sprintf("    \"type\": \"%s\",", ipamType)
		}
		c += fmt.Sprintf(inputIPAMTemplate, routes, extra)
		c += "\n}"

		return c
	}

	var makeInput = func(inputIPAM string, subnetFile string) string {
		ipamPart := ""
		if len(inputIPAM) > 0 {
			ipamPart = ",\n  \"ipam\":\n" + inputIPAM
		}

		return fmt.Sprintf(inputTemplate, subnetFile, dataDir, ipamPart)
	}

	BeforeEach(func() {
		var err error
		// flannel subnet.env
		onlyIpv4SubnetFile = writeSubnetEnv(onlyIpv4FlannelSubnetEnv)
		onlyIpv6SubnetFile = writeSubnetEnv(onlyIpv6FlannelSubnetEnv)
		dualStackSubnetFile = writeSubnetEnv(dualStackFlannelSubnetEnv)

		// flannel state dir
		dataDir, err = ioutil.TempDir("", "dataDir")
		Expect(err).NotTo(HaveOccurred())
		onlyIpv4Input = makeInput("", onlyIpv4SubnetFile)
		onlyIpv6Input = makeInput("", onlyIpv6SubnetFile)
		dualStackInput = makeInput("", dualStackSubnetFile)
	})

	AfterEach(func() {
		os.Remove(onlyIpv4SubnetFile)
		os.Remove(onlyIpv6SubnetFile)
		os.Remove(dualStackSubnetFile)
		os.Remove(dataDir)
	})

	Describe("CNI lifecycle", func() {
		Context("when using only ipv4 stack", func() {
			It("uses dataDir for storing network configuration with ipv4 stack", func() {
				const IFNAME = "eth0"

				targetNs, err := testutils.NewNS()
				Expect(err).NotTo(HaveOccurred())
				defer targetNs.Close()

				args := &skel.CmdArgs{
					ContainerID: "some-container-id-ipv4",
					Netns:       targetNs.Path(),
					IfName:      IFNAME,
					StdinData:   []byte(onlyIpv4Input),
				}

				err = originalNS.Do(func(ns.NetNS) error {
					defer GinkgoRecover()

					By("calling ADD with ipv4 stack")
					resI, _, err := testutils.CmdAddWithArgs(args, func() error {
						return cmdAdd(args)
					})
					Expect(err).NotTo(HaveOccurred())

					By("check that plugin writes the net config to dataDir with ipv4 stack")
					path := fmt.Sprintf("%s/%s", dataDir, "some-container-id-ipv4")
					Expect(path).Should(BeAnExistingFile())

					netConfBytes, err := ioutil.ReadFile(path)
					Expect(err).NotTo(HaveOccurred())
					expected := `{
    "ipMasq": false,
    "ipam": {
        "routes": [
            {
                "dst": "10.1.0.0/16"
            }
        ],
        "ranges": [
            [{
                "subnet": "10.1.17.0/24"
            }]
        ],
        "type": "host-local"
    },
    "isGateway": true,
    "mtu": 1472,
    "name": "cni-flannel",
    "type": "bridge"
}
`
					Expect(netConfBytes).Should(MatchJSON(expected))

					result, err := current.NewResultFromResult(resI)
					Expect(err).NotTo(HaveOccurred())
					Expect(result.IPs).To(HaveLen(1))

					By("calling DEL with ipv4 stack")
					err = testutils.CmdDelWithArgs(args, func() error {
						return cmdDel(args)
					})
					Expect(err).NotTo(HaveOccurred())

					By("check that plugin removes net config from state dir with ipv4 stack")
					Expect(path).ShouldNot(BeAnExistingFile())

					By("calling DEL again with ipv4 stack")
					err = testutils.CmdDelWithArgs(args, func() error {
						return cmdDel(args)
					})
					By("check that plugin does not fail due to missing net config with ipv4 stack")
					Expect(err).NotTo(HaveOccurred())

					return nil
				})
				Expect(err).NotTo(HaveOccurred())
			})
		})

		Context("when using only ipv6 stack", func() {
			It("uses dataDir for storing network configuration with ipv6 stack", func() {
				const IFNAME = "eth0"

				targetNs, err := testutils.NewNS()
				Expect(err).NotTo(HaveOccurred())
				defer targetNs.Close()

				args := &skel.CmdArgs{
					ContainerID: "some-container-id-ipv6",
					Netns:       targetNs.Path(),
					IfName:      IFNAME,
					StdinData:   []byte(onlyIpv6Input),
				}

				err = originalNS.Do(func(ns.NetNS) error {
					defer GinkgoRecover()

					By("calling ADD with ipv6 stack")
					resI, _, err := testutils.CmdAddWithArgs(args, func() error {
						return cmdAdd(args)
					})
					Expect(err).NotTo(HaveOccurred())

					By("check that plugin writes the net config to dataDir with ipv6 stack")
					path := fmt.Sprintf("%s/%s", dataDir, "some-container-id-ipv6")
					Expect(path).Should(BeAnExistingFile())

					netConfBytes, err := ioutil.ReadFile(path)
					Expect(err).NotTo(HaveOccurred())
					expected := `{
    "ipMasq": false,
    "ipam": {
        "routes": [
            {
                "dst": "fc00::/48"
            }
        ],
        "ranges": [
            [{
                "subnet": "fc00::/64"
            }]
        ],
        "type": "host-local"
    },
    "isGateway": true,
    "mtu": 1472,
    "name": "cni-flannel",
    "type": "bridge"
}
`
					Expect(netConfBytes).Should(MatchJSON(expected))

					result, err := current.NewResultFromResult(resI)
					Expect(err).NotTo(HaveOccurred())
					Expect(result.IPs).To(HaveLen(1))

					By("calling DEL with ipv6 stack")
					err = testutils.CmdDelWithArgs(args, func() error {
						return cmdDel(args)
					})
					Expect(err).NotTo(HaveOccurred())

					By("check that plugin removes net config from state dir with ipv6 stack")
					Expect(path).ShouldNot(BeAnExistingFile())

					By("calling DEL again with ipv6 stack")
					err = testutils.CmdDelWithArgs(args, func() error {
						return cmdDel(args)
					})
					By("check that plugin does not fail due to missing net config with ipv6 stack")
					Expect(err).NotTo(HaveOccurred())

					return nil
				})
				Expect(err).NotTo(HaveOccurred())
			})
		})

		Context("when using dual stack", func() {
			It("uses dataDir for storing network configuration with dual stack", func() {
				const IFNAME = "eth0"

				targetNs, err := testutils.NewNS()
				Expect(err).NotTo(HaveOccurred())
				defer targetNs.Close()

				args := &skel.CmdArgs{
					ContainerID: "some-container-id-dual-stack",
					Netns:       targetNs.Path(),
					IfName:      IFNAME,
					StdinData:   []byte(dualStackInput),
				}

				err = originalNS.Do(func(ns.NetNS) error {
					defer GinkgoRecover()

					By("calling ADD with dual stack")
					resI, _, err := testutils.CmdAddWithArgs(args, func() error {
						return cmdAdd(args)
					})
					Expect(err).NotTo(HaveOccurred())

					By("check that plugin writes the net config to dataDir with dual stack")
					path := fmt.Sprintf("%s/%s", dataDir, "some-container-id-dual-stack")
					Expect(path).Should(BeAnExistingFile())

					netConfBytes, err := ioutil.ReadFile(path)
					Expect(err).NotTo(HaveOccurred())
					expected := `{
    "ipMasq": false,
    "ipam": {
        "routes": [
            {
                "dst": "10.1.0.0/16"
            },
            {
                "dst": "fc00::/48"
            }
        ],
        "ranges": [
            [{
                "subnet": "10.1.17.0/24"
            }],
            [{
                "subnet": "fc00::/64"
            }]
        ],
        "type": "host-local"
    },
    "isGateway": true,
    "mtu": 1472,
    "name": "cni-flannel",
    "type": "bridge"
}
`
					Expect(netConfBytes).Should(MatchJSON(expected))

					result, err := current.NewResultFromResult(resI)
					Expect(err).NotTo(HaveOccurred())
					Expect(result.IPs).To(HaveLen(2))

					By("calling DEL with dual stack")
					err = testutils.CmdDelWithArgs(args, func() error {
						return cmdDel(args)
					})
					Expect(err).NotTo(HaveOccurred())

					By("check that plugin removes net config from state dir with dual stack")
					Expect(path).ShouldNot(BeAnExistingFile())

					By("calling DEL again with dual stack")
					err = testutils.CmdDelWithArgs(args, func() error {
						return cmdDel(args)
					})
					By("check that plugin does not fail due to missing net config with dual stack")
					Expect(err).NotTo(HaveOccurred())

					return nil
				})
				Expect(err).NotTo(HaveOccurred())
			})
		})
	})

	Describe("loadFlannelNetConf", func() {
		Context("when subnetFile and dataDir are specified with ipv4 stack", func() {
			It("loads flannel network config with ipv4 stack", func() {
				conf, err := loadFlannelNetConf([]byte(onlyIpv4Input))
				Expect(err).ShouldNot(HaveOccurred())
				Expect(conf.Name).To(Equal("cni-flannel"))
				Expect(conf.Type).To(Equal("flannel"))
				Expect(conf.SubnetFile).To(Equal(onlyIpv4SubnetFile))
				Expect(conf.DataDir).To(Equal(dataDir))
			})
		})

		Context("when subnetFile and dataDir are specified with ipv6 stack", func() {
			It("loads flannel network config with ipv6 stack", func() {
				conf, err := loadFlannelNetConf([]byte(onlyIpv6Input))
				Expect(err).ShouldNot(HaveOccurred())
				Expect(conf.Name).To(Equal("cni-flannel"))
				Expect(conf.Type).To(Equal("flannel"))
				Expect(conf.SubnetFile).To(Equal(onlyIpv6SubnetFile))
				Expect(conf.DataDir).To(Equal(dataDir))
			})
		})

		Context("when subnetFile and dataDir are specified with dual stack", func() {
			It("loads flannel network config with dual stack", func() {
				conf, err := loadFlannelNetConf([]byte(dualStackInput))
				Expect(err).ShouldNot(HaveOccurred())
				Expect(conf.Name).To(Equal("cni-flannel"))
				Expect(conf.Type).To(Equal("flannel"))
				Expect(conf.SubnetFile).To(Equal(dualStackSubnetFile))
				Expect(conf.DataDir).To(Equal(dataDir))
			})
		})

		Context("when defaulting subnetFile and dataDir with ipv4 stack", func() {
			BeforeEach(func() {
				onlyIpv4Input = `{
"name": "cni-flannel",
"type": "flannel"
}`
			})

			It("loads flannel network config with defaults with ipv4 stack", func() {
				conf, err := loadFlannelNetConf([]byte(onlyIpv4Input))
				Expect(err).ShouldNot(HaveOccurred())
				Expect(conf.Name).To(Equal("cni-flannel"))
				Expect(conf.Type).To(Equal("flannel"))
				Expect(conf.SubnetFile).To(Equal(defaultSubnetFile))
				Expect(conf.DataDir).To(Equal(defaultDataDir))
			})
		})

		Context("when defaulting subnetFile and dataDir with ipv6 stack", func() {
			BeforeEach(func() {
				onlyIpv6Input = `{
"name": "cni-flannel",
"type": "flannel"
}`
			})

			It("loads flannel network config with defaults with ipv6 stack", func() {
				conf, err := loadFlannelNetConf([]byte(onlyIpv6Input))
				Expect(err).ShouldNot(HaveOccurred())
				Expect(conf.Name).To(Equal("cni-flannel"))
				Expect(conf.Type).To(Equal("flannel"))
				Expect(conf.SubnetFile).To(Equal(defaultSubnetFile))
				Expect(conf.DataDir).To(Equal(defaultDataDir))
			})
		})

		Context("when defaulting subnetFile and dataDir with dual stack", func() {
			BeforeEach(func() {
				dualStackInput = `{
"name": "cni-flannel",
"type": "flannel"
}`
			})

			It("loads flannel network config with defaults with dual stack", func() {
				conf, err := loadFlannelNetConf([]byte(dualStackInput))
				Expect(err).ShouldNot(HaveOccurred())
				Expect(conf.Name).To(Equal("cni-flannel"))
				Expect(conf.Type).To(Equal("flannel"))
				Expect(conf.SubnetFile).To(Equal(defaultSubnetFile))
				Expect(conf.DataDir).To(Equal(defaultDataDir))
			})
		})

		Describe("loadFlannelSubnetEnv", func() {
			Context("when flannel subnet env is valid with ipv4 stack", func() {
				It("loads flannel subnet config with ipv4 stack", func() {
					conf, err := loadFlannelSubnetEnv(onlyIpv4SubnetFile)
					Expect(err).ShouldNot(HaveOccurred())
					Expect(conf.nw.String()).To(Equal("10.1.0.0/16"))
					Expect(conf.sn.String()).To(Equal("10.1.17.0/24"))
					var mtu uint = 1472
					Expect(*conf.mtu).To(Equal(mtu))
					Expect(*conf.ipmasq).To(BeTrue())
				})
			})

			Context("when flannel subnet env is valid with ipv6 stack", func() {
				It("loads flannel subnet config with ipv6 stack", func() {
					conf, err := loadFlannelSubnetEnv(onlyIpv6SubnetFile)
					Expect(err).ShouldNot(HaveOccurred())
					Expect(conf.ip6Nw.String()).To(Equal("fc00::/48"))
					Expect(conf.ip6Sn.String()).To(Equal("fc00::/64"))
					var mtu uint = 1472
					Expect(*conf.mtu).To(Equal(mtu))
					Expect(*conf.ipmasq).To(BeTrue())
				})
			})

			Context("when flannel subnet env is valid with dual stack", func() {
				It("loads flannel subnet config with dual stack", func() {
					conf, err := loadFlannelSubnetEnv(dualStackSubnetFile)
					Expect(err).ShouldNot(HaveOccurred())
					Expect(conf.nw.String()).To(Equal("10.1.0.0/16"))
					Expect(conf.sn.String()).To(Equal("10.1.17.0/24"))
					Expect(conf.ip6Nw.String()).To(Equal("fc00::/48"))
					Expect(conf.ip6Sn.String()).To(Equal("fc00::/64"))
					var mtu uint = 1472
					Expect(*conf.mtu).To(Equal(mtu))
					Expect(*conf.ipmasq).To(BeTrue())
				})
			})

			Context("when flannel subnet env is invalid with ipv4 stack", func() {
				BeforeEach(func() {
					onlyIpv4SubnetFile = writeSubnetEnv("foo=bar")
				})
				It("returns an error", func() {
					_, err := loadFlannelSubnetEnv(onlyIpv4SubnetFile)
					Expect(err).To(MatchError(ContainSubstring("missing FLANNEL_NETWORK, FLANNEL_IPV6_NETWORK, FLANNEL_SUBNET, FLANNEL_IPV6_SUBNET, FLANNEL_MTU, FLANNEL_IPMASQ")))
				})
			})

			Context("when flannel subnet env is invalid with ipv6 stack", func() {
				BeforeEach(func() {
					onlyIpv6SubnetFile = writeSubnetEnv("foo=bar")
				})
				It("returns an error", func() {
					_, err := loadFlannelSubnetEnv(onlyIpv6SubnetFile)
					Expect(err).To(MatchError(ContainSubstring("missing FLANNEL_NETWORK, FLANNEL_IPV6_NETWORK, FLANNEL_SUBNET, FLANNEL_IPV6_SUBNET, FLANNEL_MTU, FLANNEL_IPMASQ")))
				})
			})

			Context("when flannel subnet env is invalid with dual stack", func() {
				BeforeEach(func() {
					dualStackSubnetFile = writeSubnetEnv("foo=bar")
				})
				It("returns an error", func() {
					_, err := loadFlannelSubnetEnv(dualStackSubnetFile)
					Expect(err).To(MatchError(ContainSubstring("missing FLANNEL_NETWORK, FLANNEL_IPV6_NETWORK, FLANNEL_SUBNET, FLANNEL_IPV6_SUBNET, FLANNEL_MTU, FLANNEL_IPMASQ")))
				})
			})
		})
	})

	Describe("getDelegateIPAM", func() {
		Context("when input IPAM is provided with ipv4 stack", func() {
			BeforeEach(func() {
				inputIPAM := makeInputIPAM(inputIPAMType, inputIPAMRoutes, "")
				onlyIpv4Input = makeInput(inputIPAM, onlyIpv4SubnetFile)
			})
			It("configures Delegate IPAM accordingly with ipv4 stack", func() {
				conf, err := loadFlannelNetConf([]byte(onlyIpv4Input))
				Expect(err).ShouldNot(HaveOccurred())
				fenv, err := loadFlannelSubnetEnv(onlyIpv4SubnetFile)
				Expect(err).ShouldNot(HaveOccurred())

				ipam, err := getDelegateIPAM(conf, fenv)
				Expect(err).ShouldNot(HaveOccurred())

				podsRoute := "{ \"dst\": \"10.1.0.0/16\" }\n"
				subnet := "\"ranges\": [[{\"subnet\": \"10.1.17.0/24\"}]]"
				expected := makeInputIPAM(inputIPAMType, inputIPAMRoutes+",\n"+podsRoute, ",\n"+subnet)
				buf, _ := json.Marshal(ipam)
				Expect(buf).Should(MatchJSON(expected))
			})
		})

		Context("when input IPAM is provided with ipv6 stack", func() {
			BeforeEach(func() {
				inputIPAM := makeInputIPAM(inputIPAMType, inputIPAMRoutes, "")
				onlyIpv6Input = makeInput(inputIPAM, onlyIpv6SubnetFile)
			})
			It("configures Delegate IPAM accordingly with ipv6 stack", func() {
				conf, err := loadFlannelNetConf([]byte(onlyIpv6Input))
				Expect(err).ShouldNot(HaveOccurred())
				fenv, err := loadFlannelSubnetEnv(onlyIpv6SubnetFile)
				Expect(err).ShouldNot(HaveOccurred())

				ipam, err := getDelegateIPAM(conf, fenv)
				Expect(err).ShouldNot(HaveOccurred())

				podsRoute := "{ \"dst\": \"fc00::/48\" }\n"
				subnet := "\"ranges\": [[{ \"subnet\": \"fc00::/64\" }]]"
				expected := makeInputIPAM(inputIPAMType, inputIPAMRoutes+",\n"+podsRoute, ",\n"+subnet)
				buf, _ := json.Marshal(ipam)
				Expect(buf).Should(MatchJSON(expected))
			})
		})

		Context("when input IPAM is provided with dual stack", func() {
			BeforeEach(func() {
				inputIPAM := makeInputIPAM(inputIPAMType, inputIPAMRoutes, "")
				dualStackInput = makeInput(inputIPAM, dualStackSubnetFile)
			})
			It("configures Delegate IPAM accordingly with dual stack", func() {
				conf, err := loadFlannelNetConf([]byte(dualStackInput))
				Expect(err).ShouldNot(HaveOccurred())
				fenv, err := loadFlannelSubnetEnv(dualStackSubnetFile)
				Expect(err).ShouldNot(HaveOccurred())

				ipam, err := getDelegateIPAM(conf, fenv)
				Expect(err).ShouldNot(HaveOccurred())

				podsRoute := "{ \"dst\": \"10.1.0.0/16\" }" + ",\n" + "{ \"dst\": \"fc00::/48\" }\n"
				subnet := "\"ranges\": [[{ \"subnet\": \"10.1.17.0/24\" }],\n[{ \"subnet\": \"fc00::/64\" }]]"
				expected := makeInputIPAM(inputIPAMType, inputIPAMRoutes+",\n"+podsRoute, ",\n"+subnet)
				buf, _ := json.Marshal(ipam)
				Expect(buf).Should(MatchJSON(expected))
			})
		})

		Context("when input IPAM is provided without 'type' with ipv4 stack", func() {
			BeforeEach(func() {
				inputIPAM := makeInputIPAM("", inputIPAMRoutes, "")
				onlyIpv4Input = makeInput(inputIPAM, onlyIpv4SubnetFile)
			})
			It("configures Delegate IPAM with 'host-local' ipam with ipv4 stack", func() {
				conf, err := loadFlannelNetConf([]byte(onlyIpv4Input))
				Expect(err).ShouldNot(HaveOccurred())
				fenv, err := loadFlannelSubnetEnv(onlyIpv4SubnetFile)
				Expect(err).ShouldNot(HaveOccurred())
				ipam, err := getDelegateIPAM(conf, fenv)
				Expect(err).ShouldNot(HaveOccurred())

				podsRoute := "{ \"dst\": \"10.1.0.0/16\" }\n"
				subnet := "\"ranges\": [[{\"subnet\": \"10.1.17.0/24\"}]]"
				expected := makeInputIPAM("host-local", inputIPAMRoutes+",\n"+podsRoute, ",\n"+subnet)
				buf, _ := json.Marshal(ipam)
				Expect(buf).Should(MatchJSON(expected))
			})
		})

		Context("when input IPAM is provided without 'type' with ipv6 stack", func() {
			BeforeEach(func() {
				inputIPAM := makeInputIPAM("", inputIPAMRoutes, "")
				onlyIpv6Input = makeInput(inputIPAM, onlyIpv6SubnetFile)
			})
			It("configures Delegate IPAM with 'host-local' ipam with ipv6 stack", func() {
				conf, err := loadFlannelNetConf([]byte(onlyIpv6Input))
				Expect(err).ShouldNot(HaveOccurred())
				fenv, err := loadFlannelSubnetEnv(onlyIpv6SubnetFile)
				Expect(err).ShouldNot(HaveOccurred())
				ipam, err := getDelegateIPAM(conf, fenv)
				Expect(err).ShouldNot(HaveOccurred())

				podsRoute := "{ \"dst\": \"fc00::/48\" }\n"
				subnet := "\"ranges\": [[{ \"subnet\": \"fc00::/64\" }]]"
				expected := makeInputIPAM("host-local", inputIPAMRoutes+",\n"+podsRoute, ",\n"+subnet)
				buf, _ := json.Marshal(ipam)
				Expect(buf).Should(MatchJSON(expected))
			})
		})

		Context("when input IPAM is provided without 'type' with dual stack", func() {
			BeforeEach(func() {
				inputIPAM := makeInputIPAM("", inputIPAMRoutes, "")
				dualStackInput = makeInput(inputIPAM, dualStackSubnetFile)
			})
			It("configures Delegate IPAM with 'host-local' ipam with dual stack", func() {
				conf, err := loadFlannelNetConf([]byte(dualStackInput))
				Expect(err).ShouldNot(HaveOccurred())
				fenv, err := loadFlannelSubnetEnv(dualStackSubnetFile)
				Expect(err).ShouldNot(HaveOccurred())
				ipam, err := getDelegateIPAM(conf, fenv)
				Expect(err).ShouldNot(HaveOccurred())

				podsRoute := "{ \"dst\": \"10.1.0.0/16\" }" + ",\n" + "{ \"dst\": \"fc00::/48\" }\n"
				subnet := "\"ranges\": [[{ \"subnet\": \"10.1.17.0/24\" }],\n[{ \"subnet\": \"fc00::/64\" }]]"
				expected := makeInputIPAM("host-local", inputIPAMRoutes+",\n"+podsRoute, ",\n"+subnet)
				buf, _ := json.Marshal(ipam)
				Expect(buf).Should(MatchJSON(expected))
			})
		})
	})
})
