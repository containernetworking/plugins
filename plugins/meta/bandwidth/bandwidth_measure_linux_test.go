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
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gexec"

	"github.com/containernetworking/cni/pkg/invoke"
	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	types100 "github.com/containernetworking/cni/pkg/types/100"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/containernetworking/plugins/pkg/testutils"
)

var _ = Describe("bandwidth measure test", func() {
	var (
		hostNs          ns.NetNS
		containerNs     ns.NetNS
		hostIfname      string
		containerIfname string
		hostIP          net.IP
		containerIP     net.IP
		hostIfaceMTU    int
	)

	BeforeEach(func() {
		var err error

		hostIfname = "host-veth"
		containerIfname = "container-veth"

		hostNs, err = testutils.NewNS()
		Expect(err).NotTo(HaveOccurred())

		containerNs, err = testutils.NewNS()
		Expect(err).NotTo(HaveOccurred())

		hostIP = net.IP{169, 254, 0, 1}
		containerIP = net.IP{10, 254, 0, 1}
		hostIfaceMTU = 1024

		createVeth(hostNs, hostIfname, containerNs, containerIfname, hostIP, containerIP, hostIfaceMTU)
	})

	AfterEach(func() {
		Expect(containerNs.Close()).To(Succeed())
		Expect(testutils.UnmountNS(containerNs)).To(Succeed())
		Expect(hostNs.Close()).To(Succeed())
		Expect(testutils.UnmountNS(hostNs)).To(Succeed())
	})

	// Bandwidth requires host-side interface info, and thus only
	// supports 0.3.0 and later CNI versions
	for _, ver := range []string{"0.3.0", "0.3.1", "0.4.0", "1.0.0"} {
		Describe(fmt.Sprintf("[%s] QoS effective", ver), func() {
			Context(fmt.Sprintf("[%s] when chaining bandwidth plugin with PTP", ver), func() {
				var ptpConf string
				var rateInBits uint64
				var burstInBits uint64
				var packetInBytes int
				var containerWithoutQoSNS ns.NetNS
				var containerWithQoSNS ns.NetNS
				var portServerWithQoS int
				var portServerWithoutQoS int

				var containerWithQoSRes types.Result
				var containerWithoutQoSRes types.Result
				var echoServerWithQoS *gexec.Session
				var echoServerWithoutQoS *gexec.Session
				var dataDir string

				BeforeEach(func() {
					rateInBytes := 1000
					rateInBits = uint64(rateInBytes * 8)
					burstInBits = rateInBits * 2

					// NOTE: Traffic shapping is not that precise at low rates, would be better to use higher rates + simple time+netcat for data transfer, rather than the provided
					// client/server bin (limited to small amount of data)
					packetInBytes = rateInBytes * 3

					var err error
					dataDir, err = os.MkdirTemp("", "bandwidth_linux_test")
					Expect(err).NotTo(HaveOccurred())

					ptpConf = fmt.Sprintf(`{
						"cniVersion": "%s",
						"name": "myBWnet",
						"type": "ptp",
						"ipMasq": true,
						"mtu": 512,
						"ipam": {
						"type": "host-local",
						"subnet": "10.1.2.0/24",
						"dataDir": "%s"
						}
					}`, ver, dataDir)

					const (
						containerWithQoSIFName    = "ptp0"
						containerWithoutQoSIFName = "ptp1"
					)

					containerWithQoSNS, err = testutils.NewNS()
					Expect(err).NotTo(HaveOccurred())

					containerWithoutQoSNS, err = testutils.NewNS()
					Expect(err).NotTo(HaveOccurred())

					By("create two containers, and use the bandwidth plugin on one of them")
					Expect(hostNs.Do(func(ns.NetNS) error {
						defer GinkgoRecover()

						containerWithQoSRes, _, err = testutils.CmdAdd(containerWithQoSNS.Path(), "dummy", containerWithQoSIFName, []byte(ptpConf), func() error {
							r, err := invoke.DelegateAdd(context.TODO(), "ptp", []byte(ptpConf), nil)
							Expect(err).NotTo(HaveOccurred())
							Expect(r.Print()).To(Succeed())

							return err
						})
						Expect(err).NotTo(HaveOccurred())

						containerWithoutQoSRes, _, err = testutils.CmdAdd(containerWithoutQoSNS.Path(), "dummy2", containerWithoutQoSIFName, []byte(ptpConf), func() error {
							r, err := invoke.DelegateAdd(context.TODO(), "ptp", []byte(ptpConf), nil)
							Expect(err).NotTo(HaveOccurred())
							Expect(r.Print()).To(Succeed())

							return err
						})
						Expect(err).NotTo(HaveOccurred())

						containerWithQoSResult, err := types100.GetResult(containerWithQoSRes)
						Expect(err).NotTo(HaveOccurred())

						bandwidthPluginConf := &PluginConf{}
						err = json.Unmarshal([]byte(ptpConf), &bandwidthPluginConf)
						Expect(err).NotTo(HaveOccurred())

						bandwidthPluginConf.RuntimeConfig.Bandwidth = &BandwidthEntry{
							IngressBurst: burstInBits,
							IngressRate:  rateInBits,
							EgressBurst:  burstInBits,
							EgressRate:   rateInBits,
						}
						bandwidthPluginConf.Type = "bandwidth"
						newConfBytes, err := buildOneConfig(ver, bandwidthPluginConf, containerWithQoSResult)
						Expect(err).NotTo(HaveOccurred())

						args := &skel.CmdArgs{
							ContainerID: "dummy3",
							Netns:       containerWithQoSNS.Path(),
							IfName:      containerWithQoSIFName,
							StdinData:   newConfBytes,
						}

						result, out, err := testutils.CmdAdd(containerWithQoSNS.Path(), args.ContainerID, "", newConfBytes, func() error { return cmdAdd(args) })
						Expect(err).NotTo(HaveOccurred(), string(out))

						if testutils.SpecVersionHasCHECK(ver) {
							// Do CNI Check
							checkConf := &PluginConf{}
							err = json.Unmarshal([]byte(ptpConf), &checkConf)
							Expect(err).NotTo(HaveOccurred())

							checkConf.RuntimeConfig.Bandwidth = &BandwidthEntry{
								IngressBurst: burstInBits,
								IngressRate:  rateInBits,
								EgressBurst:  burstInBits,
								EgressRate:   rateInBits,
							}
							checkConf.Type = "bandwidth"

							newCheckBytes, err := buildOneConfig(ver, checkConf, result)
							Expect(err).NotTo(HaveOccurred())

							args = &skel.CmdArgs{
								ContainerID: "dummy3",
								Netns:       containerWithQoSNS.Path(),
								IfName:      containerWithQoSIFName,
								StdinData:   newCheckBytes,
							}

							err = testutils.CmdCheck(containerWithQoSNS.Path(), args.ContainerID, "", func() error { return cmdCheck(args) })
							Expect(err).NotTo(HaveOccurred())
						}

						return nil
					})).To(Succeed())

					By("starting a tcp server on both containers")
					portServerWithQoS, echoServerWithQoS = startEchoServerInNamespace(containerWithQoSNS)
					portServerWithoutQoS, echoServerWithoutQoS = startEchoServerInNamespace(containerWithoutQoSNS)
				})

				AfterEach(func() {
					Expect(os.RemoveAll(dataDir)).To(Succeed())

					Expect(containerWithQoSNS.Close()).To(Succeed())
					Expect(testutils.UnmountNS(containerWithQoSNS)).To(Succeed())
					Expect(containerWithoutQoSNS.Close()).To(Succeed())
					Expect(testutils.UnmountNS(containerWithoutQoSNS)).To(Succeed())

					if echoServerWithoutQoS != nil {
						echoServerWithoutQoS.Kill()
					}
					if echoServerWithQoS != nil {
						echoServerWithQoS.Kill()
					}
				})

				It("limits ingress traffic on veth device", func() {
					var runtimeWithLimit time.Duration
					var runtimeWithoutLimit time.Duration

					By("gather timing statistics about both containers")

					By("sending tcp traffic to the container that has traffic shaped", func() {
						start := time.Now()
						result, err := types100.GetResult(containerWithQoSRes)
						Expect(err).NotTo(HaveOccurred())
						makeTCPClientInNS(hostNs.Path(), result.IPs[0].Address.IP.String(), portServerWithQoS, packetInBytes)
						end := time.Now()
						runtimeWithLimit = end.Sub(start)
						log.Printf("Elapsed with qos %.2f", runtimeWithLimit.Seconds())
					})

					By("sending tcp traffic to the container that does not have traffic shaped", func() {
						start := time.Now()
						result, err := types100.GetResult(containerWithoutQoSRes)
						Expect(err).NotTo(HaveOccurred())
						makeTCPClientInNS(hostNs.Path(), result.IPs[0].Address.IP.String(), portServerWithoutQoS, packetInBytes)
						end := time.Now()
						runtimeWithoutLimit = end.Sub(start)
						log.Printf("Elapsed without qos %.2f", runtimeWithoutLimit.Seconds())
					})

					Expect(runtimeWithLimit).To(BeNumerically(">", runtimeWithoutLimit+1000*time.Millisecond))
				})
			})
		})

		Context(fmt.Sprintf("[%s] when chaining bandwidth plugin with PTP and excluding specific subnets from traffic", ver), func() {
			var ptpConf string
			var rateInBits uint64
			var burstInBits uint64
			var packetInBytes int
			var containerWithoutQoSNS ns.NetNS
			var containerWithQoSNS ns.NetNS
			var portServerWithQoS int
			var portServerWithoutQoS int

			var containerWithQoSRes types.Result
			var containerWithoutQoSRes types.Result
			var echoServerWithQoS *gexec.Session
			var echoServerWithoutQoS *gexec.Session
			var dataDir string

			BeforeEach(func() {
				rateInBytes := 1000
				rateInBits = uint64(rateInBytes * 8)
				burstInBits = rateInBits * 2
				unshapedSubnets := []string{"10.1.2.0/24"}
				// NOTE: Traffic shapping is not that precise at low rates, would be better to use higher rates + simple time+netcat for data transfer, rather than the provided
				// client/server bin (limited to small amount of data)
				packetInBytes = rateInBytes * 3

				var err error
				dataDir, err = os.MkdirTemp("", "bandwidth_linux_test")
				Expect(err).NotTo(HaveOccurred())

				ptpConf = fmt.Sprintf(`{
					"cniVersion": "%s",
					"name": "myBWnet",
					"type": "ptp",
					"ipMasq": true,
					"mtu": 512,
					"ipam": {
					"type": "host-local",
					"subnet": "10.1.2.0/24",
					"dataDir": "%s"
					}
				}`, ver, dataDir)

				const (
					containerWithQoSIFName    = "ptp0"
					containerWithoutQoSIFName = "ptp1"
				)

				containerWithQoSNS, err = testutils.NewNS()
				Expect(err).NotTo(HaveOccurred())

				containerWithoutQoSNS, err = testutils.NewNS()
				Expect(err).NotTo(HaveOccurred())

				By("create two containers, and use the bandwidth plugin on one of them")
				Expect(hostNs.Do(func(ns.NetNS) error {
					defer GinkgoRecover()

					containerWithQoSRes, _, err = testutils.CmdAdd(containerWithQoSNS.Path(), "dummy", containerWithQoSIFName, []byte(ptpConf), func() error {
						r, err := invoke.DelegateAdd(context.TODO(), "ptp", []byte(ptpConf), nil)
						Expect(err).NotTo(HaveOccurred())
						Expect(r.Print()).To(Succeed())

						return err
					})
					Expect(err).NotTo(HaveOccurred())

					containerWithoutQoSRes, _, err = testutils.CmdAdd(containerWithoutQoSNS.Path(), "dummy2", containerWithoutQoSIFName, []byte(ptpConf), func() error {
						r, err := invoke.DelegateAdd(context.TODO(), "ptp", []byte(ptpConf), nil)
						Expect(err).NotTo(HaveOccurred())
						Expect(r.Print()).To(Succeed())

						return err
					})
					Expect(err).NotTo(HaveOccurred())

					containerWithQoSResult, err := types100.GetResult(containerWithQoSRes)
					Expect(err).NotTo(HaveOccurred())

					bandwidthPluginConf := &PluginConf{}
					err = json.Unmarshal([]byte(ptpConf), &bandwidthPluginConf)
					Expect(err).NotTo(HaveOccurred())

					bandwidthPluginConf.RuntimeConfig.Bandwidth = &BandwidthEntry{
						IngressBurst:    burstInBits,
						IngressRate:     rateInBits,
						EgressBurst:     burstInBits,
						EgressRate:      rateInBits,
						UnshapedSubnets: unshapedSubnets,
					}
					bandwidthPluginConf.Type = "bandwidth"
					newConfBytes, err := buildOneConfig(ver, bandwidthPluginConf, containerWithQoSResult)
					Expect(err).NotTo(HaveOccurred())

					args := &skel.CmdArgs{
						ContainerID: "dummy3",
						Netns:       containerWithQoSNS.Path(),
						IfName:      containerWithQoSIFName,
						StdinData:   newConfBytes,
					}

					result, out, err := testutils.CmdAdd(containerWithQoSNS.Path(), args.ContainerID, "", newConfBytes, func() error { return cmdAdd(args) })
					Expect(err).NotTo(HaveOccurred(), string(out))

					if testutils.SpecVersionHasCHECK(ver) {
						// Do CNI Check
						checkConf := &PluginConf{}
						err = json.Unmarshal([]byte(ptpConf), &checkConf)
						Expect(err).NotTo(HaveOccurred())

						checkConf.RuntimeConfig.Bandwidth = &BandwidthEntry{
							IngressBurst:    burstInBits,
							IngressRate:     rateInBits,
							EgressBurst:     burstInBits,
							EgressRate:      rateInBits,
							UnshapedSubnets: unshapedSubnets,
						}
						checkConf.Type = "bandwidth"

						newCheckBytes, err := buildOneConfig(ver, checkConf, result)
						Expect(err).NotTo(HaveOccurred())

						args = &skel.CmdArgs{
							ContainerID: "dummy3",
							Netns:       containerWithQoSNS.Path(),
							IfName:      containerWithQoSIFName,
							StdinData:   newCheckBytes,
						}

						err = testutils.CmdCheck(containerWithQoSNS.Path(), args.ContainerID, "", func() error { return cmdCheck(args) })
						Expect(err).NotTo(HaveOccurred())
					}

					return nil
				})).To(Succeed())

				By("starting a tcp server on both containers")
				portServerWithQoS, echoServerWithQoS = startEchoServerInNamespace(containerWithQoSNS)
				portServerWithoutQoS, echoServerWithoutQoS = startEchoServerInNamespace(containerWithoutQoSNS)
			})

			AfterEach(func() {
				Expect(os.RemoveAll(dataDir)).To(Succeed())

				Expect(containerWithQoSNS.Close()).To(Succeed())
				Expect(testutils.UnmountNS(containerWithQoSNS)).To(Succeed())
				Expect(containerWithoutQoSNS.Close()).To(Succeed())
				Expect(testutils.UnmountNS(containerWithoutQoSNS)).To(Succeed())

				if echoServerWithoutQoS != nil {
					echoServerWithoutQoS.Kill()
				}
				if echoServerWithQoS != nil {
					echoServerWithQoS.Kill()
				}
			})

			It("does not limits ingress traffic on veth device coming from 10.1.2.0/24", func() {
				var runtimeWithLimit time.Duration
				var runtimeWithoutLimit time.Duration

				By("gather timing statistics about both containers")

				By("sending tcp traffic to the container that has traffic shaped", func() {
					start := time.Now()
					result, err := types100.GetResult(containerWithQoSRes)
					Expect(err).NotTo(HaveOccurred())
					makeTCPClientInNS(hostNs.Path(), result.IPs[0].Address.IP.String(), portServerWithQoS, packetInBytes)
					end := time.Now()
					runtimeWithLimit = end.Sub(start)
					log.Printf("Elapsed with qos %.2f", runtimeWithLimit.Seconds())
				})

				By("sending tcp traffic to the container that does not have traffic shaped", func() {
					start := time.Now()
					result, err := types100.GetResult(containerWithoutQoSRes)
					Expect(err).NotTo(HaveOccurred())
					makeTCPClientInNS(hostNs.Path(), result.IPs[0].Address.IP.String(), portServerWithoutQoS, packetInBytes)
					end := time.Now()
					runtimeWithoutLimit = end.Sub(start)
					log.Printf("Elapsed without qos %.2f", runtimeWithoutLimit.Seconds())
				})

				Expect(runtimeWithLimit - runtimeWithoutLimit).To(BeNumerically("<", 100*time.Millisecond))
			})
		})

		Context(fmt.Sprintf("[%s] when chaining bandwidth plugin with PTP and only including specific subnets in traffic shapping (not including the main ns one)", ver), func() {
			var ptpConf string
			var rateInBits uint64
			var burstInBits uint64
			var packetInBytes int
			var containerWithoutQoSNS ns.NetNS
			var containerWithQoSNS ns.NetNS
			var portServerWithQoS int
			var portServerWithoutQoS int

			var containerWithQoSRes types.Result
			var containerWithoutQoSRes types.Result
			var echoServerWithQoS *gexec.Session
			var echoServerWithoutQoS *gexec.Session
			var dataDir string

			BeforeEach(func() {
				rateInBytes := 1000
				rateInBits = uint64(rateInBytes * 8)
				burstInBits = rateInBits * 2
				shapedSubnets := []string{"10.2.2.0/24"}
				// NOTE: Traffic shapping is not that precise at low rates, would be better to use higher rates + simple time+netcat for data transfer, rather than the provided
				// client/server bin (limited to small amount of data)
				packetInBytes = rateInBytes * 3

				var err error
				dataDir, err = os.MkdirTemp("", "bandwidth_linux_test")
				Expect(err).NotTo(HaveOccurred())

				ptpConf = fmt.Sprintf(`{
					"cniVersion": "%s",
					"name": "myBWnet",
					"type": "ptp",
					"ipMasq": true,
					"mtu": 512,
					"ipam": {
					"type": "host-local",
					"subnet": "10.1.2.0/24",
					"dataDir": "%s"
					}
				}`, ver, dataDir)

				const (
					containerWithQoSIFName    = "ptp0"
					containerWithoutQoSIFName = "ptp1"
				)

				containerWithQoSNS, err = testutils.NewNS()
				Expect(err).NotTo(HaveOccurred())

				containerWithoutQoSNS, err = testutils.NewNS()
				Expect(err).NotTo(HaveOccurred())

				By("create two containers, and use the bandwidth plugin on one of them")

				Expect(hostNs.Do(func(ns.NetNS) error {
					defer GinkgoRecover()

					containerWithQoSRes, _, err = testutils.CmdAdd(containerWithQoSNS.Path(), "dummy", containerWithQoSIFName, []byte(ptpConf), func() error {
						r, err := invoke.DelegateAdd(context.TODO(), "ptp", []byte(ptpConf), nil)
						Expect(err).NotTo(HaveOccurred())
						Expect(r.Print()).To(Succeed())

						return err
					})
					Expect(err).NotTo(HaveOccurred())

					containerWithoutQoSRes, _, err = testutils.CmdAdd(containerWithoutQoSNS.Path(), "dummy2", containerWithoutQoSIFName, []byte(ptpConf), func() error {
						r, err := invoke.DelegateAdd(context.TODO(), "ptp", []byte(ptpConf), nil)
						Expect(err).NotTo(HaveOccurred())
						Expect(r.Print()).To(Succeed())

						return err
					})
					Expect(err).NotTo(HaveOccurred())

					containerWithQoSResult, err := types100.GetResult(containerWithQoSRes)
					Expect(err).NotTo(HaveOccurred())

					bandwidthPluginConf := &PluginConf{}
					err = json.Unmarshal([]byte(ptpConf), &bandwidthPluginConf)
					Expect(err).NotTo(HaveOccurred())

					bandwidthPluginConf.RuntimeConfig.Bandwidth = &BandwidthEntry{
						IngressBurst:  burstInBits,
						IngressRate:   rateInBits,
						EgressBurst:   burstInBits,
						EgressRate:    rateInBits,
						ShapedSubnets: shapedSubnets,
					}
					bandwidthPluginConf.Type = "bandwidth"
					newConfBytes, err := buildOneConfig(ver, bandwidthPluginConf, containerWithQoSResult)
					Expect(err).NotTo(HaveOccurred())

					args := &skel.CmdArgs{
						ContainerID: "dummy3",
						Netns:       containerWithQoSNS.Path(),
						IfName:      containerWithQoSIFName,
						StdinData:   newConfBytes,
					}

					result, out, err := testutils.CmdAdd(containerWithQoSNS.Path(), args.ContainerID, "", newConfBytes, func() error { return cmdAdd(args) })
					Expect(err).NotTo(HaveOccurred(), string(out))

					if testutils.SpecVersionHasCHECK(ver) {
						// Do CNI Check
						checkConf := &PluginConf{}
						err = json.Unmarshal([]byte(ptpConf), &checkConf)
						Expect(err).NotTo(HaveOccurred())

						checkConf.RuntimeConfig.Bandwidth = &BandwidthEntry{
							IngressBurst:  burstInBits,
							IngressRate:   rateInBits,
							EgressBurst:   burstInBits,
							EgressRate:    rateInBits,
							ShapedSubnets: shapedSubnets,
						}
						checkConf.Type = "bandwidth"

						newCheckBytes, err := buildOneConfig(ver, checkConf, result)
						Expect(err).NotTo(HaveOccurred())

						args = &skel.CmdArgs{
							ContainerID: "dummy3",
							Netns:       containerWithQoSNS.Path(),
							IfName:      containerWithQoSIFName,
							StdinData:   newCheckBytes,
						}

						err = testutils.CmdCheck(containerWithQoSNS.Path(), args.ContainerID, "", func() error { return cmdCheck(args) })
						Expect(err).NotTo(HaveOccurred())
					}

					return nil
				})).To(Succeed())

				By("starting a tcp server on both containers")
				portServerWithQoS, echoServerWithQoS = startEchoServerInNamespace(containerWithQoSNS)
				portServerWithoutQoS, echoServerWithoutQoS = startEchoServerInNamespace(containerWithoutQoSNS)
			})

			AfterEach(func() {
				Expect(os.RemoveAll(dataDir)).To(Succeed())

				Expect(containerWithQoSNS.Close()).To(Succeed())
				Expect(testutils.UnmountNS(containerWithQoSNS)).To(Succeed())
				Expect(containerWithoutQoSNS.Close()).To(Succeed())
				Expect(testutils.UnmountNS(containerWithoutQoSNS)).To(Succeed())

				if echoServerWithoutQoS != nil {
					echoServerWithoutQoS.Kill()
				}
				if echoServerWithQoS != nil {
					echoServerWithQoS.Kill()
				}
			})

			It("does not limit ingress traffic on veth device coming from non included subnets", func() {
				var runtimeWithLimit time.Duration
				var runtimeWithoutLimit time.Duration

				By("gather timing statistics about both containers")

				By("sending tcp traffic to the container that has traffic shaped", func() {
					start := time.Now()
					result, err := types100.GetResult(containerWithQoSRes)
					Expect(err).NotTo(HaveOccurred())
					makeTCPClientInNS(hostNs.Path(), result.IPs[0].Address.IP.String(), portServerWithQoS, packetInBytes)
					end := time.Now()
					runtimeWithLimit = end.Sub(start)
					log.Printf("Elapsed with qos %.2f", runtimeWithLimit.Seconds())
				})

				By("sending tcp traffic to the container that does not have traffic shaped", func() {
					start := time.Now()
					result, err := types100.GetResult(containerWithoutQoSRes)
					Expect(err).NotTo(HaveOccurred())
					makeTCPClientInNS(hostNs.Path(), result.IPs[0].Address.IP.String(), portServerWithoutQoS, packetInBytes)
					end := time.Now()
					runtimeWithoutLimit = end.Sub(start)
					log.Printf("Elapsed without qos %.2f", runtimeWithoutLimit.Seconds())
				})

				Expect(runtimeWithLimit - runtimeWithoutLimit).To(BeNumerically("<", 100*time.Millisecond))
			})
		})

		Context(fmt.Sprintf("[%s] when chaining bandwidth plugin with PTP and only including specific subnets in traffic shapping (including the main ns one)", ver), func() {
			var ptpConf string
			var rateInBits uint64
			var burstInBits uint64
			var packetInBytes int
			var containerWithoutQoSNS ns.NetNS
			var containerWithQoSNS ns.NetNS
			var portServerWithQoS int
			var portServerWithoutQoS int

			var containerWithQoSRes types.Result
			var containerWithoutQoSRes types.Result
			var echoServerWithQoS *gexec.Session
			var echoServerWithoutQoS *gexec.Session
			var dataDir string

			BeforeEach(func() {
				rateInBytes := 1000
				rateInBits = uint64(rateInBytes * 8)
				burstInBits = rateInBits * 2
				shapedSubnets := []string{"10.1.2.1/32"}
				// NOTE: Traffic shapping is not that precise at low rates, would be better to use higher rates + simple time+netcat for data transfer, rather than the provided
				// client/server bin (limited to small amount of data)
				packetInBytes = rateInBytes * 3

				var err error
				dataDir, err = os.MkdirTemp("", "bandwidth_linux_test")
				Expect(err).NotTo(HaveOccurred())

				ptpConf = fmt.Sprintf(`{
					"cniVersion": "%s",
					"name": "myBWnet",
					"type": "ptp",
					"ipMasq": true,
					"mtu": 512,
					"ipam": {
					"type": "host-local",
					"subnet": "10.1.2.0/24",
					"dataDir": "%s"
					}
				}`, ver, dataDir)

				const (
					containerWithQoSIFName    = "ptp0"
					containerWithoutQoSIFName = "ptp1"
				)

				containerWithQoSNS, err = testutils.NewNS()
				Expect(err).NotTo(HaveOccurred())

				containerWithoutQoSNS, err = testutils.NewNS()
				Expect(err).NotTo(HaveOccurred())

				By("create two containers, and use the bandwidth plugin on one of them")

				Expect(hostNs.Do(func(ns.NetNS) error {
					defer GinkgoRecover()

					containerWithQoSRes, _, err = testutils.CmdAdd(containerWithQoSNS.Path(), "dummy", containerWithQoSIFName, []byte(ptpConf), func() error {
						r, err := invoke.DelegateAdd(context.TODO(), "ptp", []byte(ptpConf), nil)
						Expect(err).NotTo(HaveOccurred())
						Expect(r.Print()).To(Succeed())

						return err
					})
					Expect(err).NotTo(HaveOccurred())

					containerWithoutQoSRes, _, err = testutils.CmdAdd(containerWithoutQoSNS.Path(), "dummy2", containerWithoutQoSIFName, []byte(ptpConf), func() error {
						r, err := invoke.DelegateAdd(context.TODO(), "ptp", []byte(ptpConf), nil)
						Expect(err).NotTo(HaveOccurred())
						Expect(r.Print()).To(Succeed())

						return err
					})
					Expect(err).NotTo(HaveOccurred())

					containerWithQoSResult, err := types100.GetResult(containerWithQoSRes)
					Expect(err).NotTo(HaveOccurred())

					bandwidthPluginConf := &PluginConf{}
					err = json.Unmarshal([]byte(ptpConf), &bandwidthPluginConf)
					Expect(err).NotTo(HaveOccurred())

					bandwidthPluginConf.RuntimeConfig.Bandwidth = &BandwidthEntry{
						IngressBurst:  burstInBits,
						IngressRate:   rateInBits,
						EgressBurst:   burstInBits,
						EgressRate:    rateInBits,
						ShapedSubnets: shapedSubnets,
					}
					bandwidthPluginConf.Type = "bandwidth"
					newConfBytes, err := buildOneConfig(ver, bandwidthPluginConf, containerWithQoSResult)
					Expect(err).NotTo(HaveOccurred())

					args := &skel.CmdArgs{
						ContainerID: "dummy3",
						Netns:       containerWithQoSNS.Path(),
						IfName:      containerWithQoSIFName,
						StdinData:   newConfBytes,
					}

					result, out, err := testutils.CmdAdd(containerWithQoSNS.Path(), args.ContainerID, "", newConfBytes, func() error { return cmdAdd(args) })
					Expect(err).NotTo(HaveOccurred(), string(out))

					if testutils.SpecVersionHasCHECK(ver) {
						// Do CNI Check
						checkConf := &PluginConf{}
						err = json.Unmarshal([]byte(ptpConf), &checkConf)
						Expect(err).NotTo(HaveOccurred())

						checkConf.RuntimeConfig.Bandwidth = &BandwidthEntry{
							IngressBurst:  burstInBits,
							IngressRate:   rateInBits,
							EgressBurst:   burstInBits,
							EgressRate:    rateInBits,
							ShapedSubnets: shapedSubnets,
						}
						checkConf.Type = "bandwidth"

						newCheckBytes, err := buildOneConfig(ver, checkConf, result)
						Expect(err).NotTo(HaveOccurred())

						args = &skel.CmdArgs{
							ContainerID: "dummy3",
							Netns:       containerWithQoSNS.Path(),
							IfName:      containerWithQoSIFName,
							StdinData:   newCheckBytes,
						}

						err = testutils.CmdCheck(containerWithQoSNS.Path(), args.ContainerID, "", func() error { return cmdCheck(args) })
						Expect(err).NotTo(HaveOccurred())
					}

					return nil
				})).To(Succeed())

				By("starting a tcp server on both containers")
				portServerWithQoS, echoServerWithQoS = startEchoServerInNamespace(containerWithQoSNS)
				portServerWithoutQoS, echoServerWithoutQoS = startEchoServerInNamespace(containerWithoutQoSNS)
			})

			AfterEach(func() {
				Expect(os.RemoveAll(dataDir)).To(Succeed())

				Expect(containerWithQoSNS.Close()).To(Succeed())
				Expect(testutils.UnmountNS(containerWithQoSNS)).To(Succeed())
				Expect(containerWithoutQoSNS.Close()).To(Succeed())
				Expect(testutils.UnmountNS(containerWithoutQoSNS)).To(Succeed())

				if echoServerWithoutQoS != nil {
					echoServerWithoutQoS.Kill()
				}
				if echoServerWithQoS != nil {
					echoServerWithQoS.Kill()
				}
			})

			It("limits ingress traffic on veth device coming from included subnets", func() {
				var runtimeWithLimit time.Duration
				var runtimeWithoutLimit time.Duration

				By("gather timing statistics about both containers")

				By("sending tcp traffic to the container that has traffic shaped", func() {
					start := time.Now()
					result, err := types100.GetResult(containerWithQoSRes)
					Expect(err).NotTo(HaveOccurred())
					makeTCPClientInNS(hostNs.Path(), result.IPs[0].Address.IP.String(), portServerWithQoS, packetInBytes)
					end := time.Now()
					runtimeWithLimit = end.Sub(start)
					log.Printf("Elapsed with qos %.2f", runtimeWithLimit.Seconds())
				})

				By("sending tcp traffic to the container that does not have traffic shaped", func() {
					start := time.Now()
					result, err := types100.GetResult(containerWithoutQoSRes)
					Expect(err).NotTo(HaveOccurred())
					makeTCPClientInNS(hostNs.Path(), result.IPs[0].Address.IP.String(), portServerWithoutQoS, packetInBytes)
					end := time.Now()
					runtimeWithoutLimit = end.Sub(start)
					log.Printf("Elapsed without qos %.2f", runtimeWithoutLimit.Seconds())
				})

				Expect(runtimeWithLimit).To(BeNumerically(">", runtimeWithoutLimit+1000*time.Millisecond))
			})
		})
	}
})
