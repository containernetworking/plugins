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
	"fmt"
	"io/ioutil"
	"os"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types/current"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/containernetworking/plugins/pkg/testutils"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"net"
)

var _ = Describe("Flannel", func() {
	var (
		originalNS ns.NetNS
		input      string
		subnetFile string
		dataDir    string
	)

	BeforeEach(func() {
		var err error
		originalNS, err = ns.NewNS()
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
	"dataDir": "%s"
}`

	const flannelSubnetEnv = `
FLANNEL_NETWORK=10.1.0.0/16
FLANNEL_SUBNET=10.1.17.1/24
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

	BeforeEach(func() {
		var err error
		// flannel subnet.env
		subnetFile = writeSubnetEnv(flannelSubnetEnv)

		// flannel state dir
		dataDir, err = ioutil.TempDir("", "dataDir")
		Expect(err).NotTo(HaveOccurred())
		input = fmt.Sprintf(inputTemplate, subnetFile, dataDir)
	})

	AfterEach(func() {
		os.Remove(subnetFile)
		os.Remove(dataDir)
	})

	Describe("CNI lifecycle", func() {
		It("uses dataDir for storing network configuration", func() {
			const IFNAME = "eth0"

			targetNs, err := ns.NewNS()
			Expect(err).NotTo(HaveOccurred())
			defer targetNs.Close()

			args := &skel.CmdArgs{
				ContainerID: "some-container-id",
				Netns:       targetNs.Path(),
				IfName:      IFNAME,
				StdinData:   []byte(input),
			}

			err = originalNS.Do(func(ns.NetNS) error {
				defer GinkgoRecover()

				By("calling ADD")
				resI, _, err := testutils.CmdAddWithResult(targetNs.Path(), IFNAME, []byte(input), func() error {
					return cmdAdd(args)
				})
				Expect(err).NotTo(HaveOccurred())

				By("check that plugin writes to net config to dataDir")
				path := fmt.Sprintf("%s/%s", dataDir, "some-container-id")
				Expect(path).Should(BeAnExistingFile())

				netConfBytes, err := ioutil.ReadFile(path)
				Expect(err).NotTo(HaveOccurred())
				expected := `{
   "ipMasq" : false,
   "ipam" : {
      "routes" : [
         {
            "dst" : "10.1.0.0/16"
         }
      ],
      "subnet" : "10.1.17.0/24",
      "type" : "host-local"
   },
   "isGateway": true,
   "mtu" : 1472,
   "name" : "cni-flannel",
   "type" : "bridge"
}
`
				Expect(netConfBytes).Should(MatchJSON(expected))

				result, err := current.NewResultFromResult(resI)
				Expect(err).NotTo(HaveOccurred())
				Expect(result.IPs).To(HaveLen(1))

				By("calling DEL")
				err = testutils.CmdDelWithResult(targetNs.Path(), IFNAME, func() error {
					return cmdDel(args)
				})
				Expect(err).NotTo(HaveOccurred())

				By("check that plugin removes net config from state dir")
				Expect(path).ShouldNot(BeAnExistingFile())

				By("calling DEL again")
				err = testutils.CmdDelWithResult(targetNs.Path(), IFNAME, func() error {
					return cmdDel(args)
				})
				By("check that plugin does not fail due to missing net config")
				Expect(err).NotTo(HaveOccurred())

				return nil
			})
			Expect(err).NotTo(HaveOccurred())
		})
	})

	Describe("windowsOutboundNat", func() {
		Context("when not set by user", func() {
			It("sets it by adding a policy", func() {
				// given a subnet config that requests ipmasq
				_, nw, _ := net.ParseCIDR("192.168.0.0/16")
				_, sn, _ := net.ParseCIDR("192.168.10.0/24")
				ipmasq := true
				fenv := &subnetEnv{
					nw:     nw,
					sn:     sn,
					ipmasq: &ipmasq,
				}

				// apply it
				delegate := make(map[string]interface{})
				updateOutboundNat(delegate, fenv)

				Expect(delegate).Should(HaveKey("AdditionalArgs"))

				addlArgs := (delegate["AdditionalArgs"]).([]interface{})
				Expect(addlArgs).Should(HaveLen(1))

				policy := addlArgs[0].(map[string]interface{})
				Expect(policy).Should(HaveKey("Name"))
				Expect(policy).Should(HaveKey("Value"))
				Expect(policy["Name"]).Should(Equal("EndpointPolicy"))

				value := policy["Value"].(map[string]interface{})
				Expect(value).Should(HaveKey("Type"))
				Expect(value).Should(HaveKey("ExceptionList"))
				Expect(value["Type"]).Should(Equal("OutBoundNAT"))

				exceptionList := value["ExceptionList"].([]interface{})
				Expect(exceptionList).Should(HaveLen(1))
				Expect(exceptionList[0].(string)).Should(Equal(nw.String()))
			})
		})

		Context("when set by user", func() {
			It("appends exceptions to the existing policy", func() {
				// given a subnet config that requests ipmasq
				_, nw, _ := net.ParseCIDR("192.168.0.0/16")
				_, sn, _ := net.ParseCIDR("192.168.10.0/24")
				ipmasq := true
				fenv := &subnetEnv{
					nw:     nw,
					sn:     sn,
					ipmasq: &ipmasq,
				}

				// first set it
				delegate := make(map[string]interface{})
				updateOutboundNat(delegate, fenv)

				// then attempt to update it
				_, nw2, _ := net.ParseCIDR("10.244.0.0/16")
				fenv.nw = nw2
				updateOutboundNat(delegate, fenv)

				// but it stays the same!
				addlArgs := (delegate["AdditionalArgs"]).([]interface{})
				policy := addlArgs[0].(map[string]interface{})
				value := policy["Value"].(map[string]interface{})
				exceptionList := value["ExceptionList"].([]interface{})

				Expect(exceptionList[0].(string)).Should(Equal(nw.String()))
				Expect(exceptionList[1].(string)).Should(Equal(nw2.String()))
			})
		})
	})

	Describe("windows delegate preparation", func() {
		var (
			fenv *subnetEnv
			n    *NetConf
		)
		BeforeEach(func() {
			_, nw, _ := net.ParseCIDR("192.168.0.0/16")
			_, sn, _ := net.ParseCIDR("192.168.10.0/24")
			ipmasq := true
			fenv = &subnetEnv{
				nw:     nw,
				sn:     sn,
				ipmasq: &ipmasq,
			}
		})
		Context("when backendType is unknown", func() {
			BeforeEach(func() {
				cniConf := []byte(`
{
	"name": "someNetwork",
	"type": "flannel",
	"delegate": {
		"backendType": "randomBackend"
	}
}
				`)
				n, _ = loadFlannelNetConf(cniConf)
			})
			It("fails with and error", func() {
				err := prepareAddWindows(n, fenv)
				Expect(err).Should(HaveOccurred())
			})
		})
		Context("when backendType is empty", func() {
			BeforeEach(func() {
				cniConf := []byte(`
{
	"name": "someNetwork",
	"type": "flannel",
	"delegate": {
	}
}
				`)
				n, _ = loadFlannelNetConf(cniConf)
			})
			It("uses a default", func() {
				err := prepareAddWindows(n, fenv)
				Expect(err).ShouldNot(HaveOccurred())

			})
		})
		Context("when backendType is host-gw", func() {
			var (
				err error
			)
			BeforeEach(func() {
				cniConf := []byte(`
{
	"name": "someNetwork",
	"type": "flannel",
	"delegate": {
		"backendType": "host-gw"
	}
}
				`)
				n, _ = loadFlannelNetConf(cniConf)
				err = prepareAddWindows(n, fenv)
			})
			It("is able to prepare", func() {
				Expect(err).ShouldNot(HaveOccurred())
			})
			It("configures IPAM as HNS", func() {
				Expect(hasKey(n.Delegate, "ipam")).Should(BeTrue())

				ipam := n.Delegate["ipam"].(map[string]interface{})
				Expect(hasKey(ipam, "type")).Should(BeFalse())
				Expect(hasKey(ipam, "subnet")).Should(BeTrue())
				Expect(ipam["subnet"].(string)).Should(Equal("192.168.10.0/24"))
				Expect(hasKey(ipam, "routes")).Should(BeTrue())

				routes := ipam["routes"].([]interface{})
				Expect(routes).Should(HaveLen(1))
				route := routes[0].(map[string]interface{})
				Expect(hasKey(route, "GW")).Should(BeTrue())
				Expect(route["GW"].(string)).Should(Equal("192.168.10.2"))
			})
		})
		Context("when backendType is vxlan", func() {
			var (
				err error
			)
			BeforeEach(func() {
				cniConf := []byte(`
{
	"name": "someNetwork",
	"type": "flannel",
	"delegate": {
		"backendType": "vxlan",
		"endpointMacPrefix": "0E-2A"
	}
}
				`)
				n, _ = loadFlannelNetConf(cniConf)
				err = prepareAddWindows(n, fenv)
			})
			It("is able to prepare", func() {
				Expect(err).ShouldNot(HaveOccurred())
			})
			It("configures IPAM as host-local", func() {
				Expect(hasKey(n.Delegate, "ipam")).Should(BeTrue())

				ipam := n.Delegate["ipam"].(map[string]interface{})
				Expect(hasKey(ipam, "type")).Should(BeTrue())
				Expect(ipam["type"].(string)).Should(Equal("host-local"))
				Expect(hasKey(ipam, "subnet")).Should(BeTrue())
				Expect(ipam["subnet"].(string)).Should(Equal("192.168.0.0/16"))
				Expect(hasKey(ipam, "rangeStart")).Should(BeTrue())
				Expect(ipam["rangeStart"].(string)).Should(Equal("192.168.10.2"))
				Expect(hasKey(ipam, "rangeEnd")).Should(BeTrue())
				Expect(ipam["rangeEnd"].(string)).Should(Equal("192.168.10.254"))
				Expect(hasKey(ipam, "gateway")).Should(BeTrue())
				Expect(ipam["gateway"].(string)).Should(Equal("192.168.0.1"))
				Expect(hasKey(ipam, "routes")).Should(BeFalse())
			})
		})
	})

	Describe("loadFlannelNetConf", func() {
		Context("when subnetFile and dataDir are specified", func() {
			It("loads flannel network config", func() {
				conf, err := loadFlannelNetConf([]byte(input))
				Expect(err).ShouldNot(HaveOccurred())
				Expect(conf.Name).To(Equal("cni-flannel"))
				Expect(conf.Type).To(Equal("flannel"))
				Expect(conf.SubnetFile).To(Equal(subnetFile))
				Expect(conf.DataDir).To(Equal(dataDir))
			})
		})

		Context("when defaulting subnetFile and dataDir", func() {
			BeforeEach(func() {
				input = `{
"name": "cni-flannel",
"type": "flannel"
}`
			})

			It("loads flannel network config with defaults", func() {
				conf, err := loadFlannelNetConf([]byte(input))
				Expect(err).ShouldNot(HaveOccurred())
				Expect(conf.Name).To(Equal("cni-flannel"))
				Expect(conf.Type).To(Equal("flannel"))
				Expect(conf.SubnetFile).To(Equal(defaultSubnetFile))
				Expect(conf.DataDir).To(Equal(defaultDataDir))
			})
		})

		Describe("loadFlannelSubnetEnv", func() {
			Context("when flannel subnet env is valid", func() {
				It("loads flannel subnet config", func() {
					conf, err := loadFlannelSubnetEnv(subnetFile)
					Expect(err).ShouldNot(HaveOccurred())
					Expect(conf.nw.String()).To(Equal("10.1.0.0/16"))
					Expect(conf.sn.String()).To(Equal("10.1.17.0/24"))
					var mtu uint = 1472
					Expect(*conf.mtu).To(Equal(mtu))
					Expect(*conf.ipmasq).To(BeTrue())
				})
			})

			Context("when flannel subnet env is invalid", func() {
				BeforeEach(func() {
					subnetFile = writeSubnetEnv("foo=bar")
				})
				It("returns an error", func() {
					_, err := loadFlannelSubnetEnv(subnetFile)
					Expect(err).To(MatchError(ContainSubstring("missing FLANNEL_NETWORK, FLANNEL_SUBNET, FLANNEL_MTU, FLANNEL_IPMASQ")))
				})
			})
		})
	})
})
