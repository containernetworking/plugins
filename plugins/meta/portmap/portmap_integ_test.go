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
	"bytes"
	"context"
	"fmt"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/coreos/go-iptables/iptables"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gexec"
	"github.com/vishvananda/netlink"

	"github.com/containernetworking/cni/libcni"
	"github.com/containernetworking/cni/pkg/types/100"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/containernetworking/plugins/pkg/testutils"
)

func makeConfig(ver string) *libcni.NetworkConfigList {
	configList, err := libcni.ConfListFromBytes([]byte(fmt.Sprintf(`{
		"cniVersion": "%s",
		"name": "cni-portmap-unit-test",
		"plugins": [
			{
				"type": "ptp",
				"ipMasq": true,
				"ipam": {
					"type": "host-local",
					"subnet": "172.16.31.0/24",
					"routes": [
						{"dst": "0.0.0.0/0"}
					]
				}
			},
			{
				"type": "portmap",
				"capabilities": {
					"portMappings": true
				}
			}
		]
	}`, ver)))
	Expect(err).NotTo(HaveOccurred())
	return configList
}

var _ = Describe("portmap integration tests", func() {
	var (
		cniConf       *libcni.CNIConfig
		targetNS      ns.NetNS
		containerPort int
		session       *gexec.Session
	)

	BeforeEach(func() {
		// turn PATH in to CNI_PATH
		dirs := filepath.SplitList(os.Getenv("PATH"))
		cniConf = &libcni.CNIConfig{Path: dirs}

		var err error
		targetNS, err = testutils.NewNS()
		Expect(err).NotTo(HaveOccurred())
		fmt.Fprintln(GinkgoWriter, "namespace:", targetNS.Path())

		// Start an echo server and get the port
		containerPort, session = StartEchoServerInNamespace(targetNS)
	})

	AfterEach(func() {
		session.Terminate().Wait()
		targetNS.Close()
		testutils.UnmountNS(targetNS)
	})

	for _, ver := range []string{"0.3.0", "0.3.1", "0.4.0", "1.0.0"} {
		// Redefine ver inside for scope so real value is picked up by each dynamically defined It()
		// See Gingkgo's "Patterns for dynamically generating tests" documentation.
		ver := ver

		Describe("Creating an interface in a namespace with the ptp plugin", func() {
			// This needs to be done using Ginkgo's asynchronous testing mode.
			It(fmt.Sprintf("[%s] forwards a TCP port on ipv4", ver), func(done Done) {
				var err error
				hostPort := rand.Intn(10000) + 1025
				runtimeConfig := libcni.RuntimeConf{
					ContainerID: fmt.Sprintf("unit-test-%d", hostPort),
					NetNS:       targetNS.Path(),
					IfName:      "eth0",
					CapabilityArgs: map[string]interface{}{
						"portMappings": []map[string]interface{}{
							{
								"hostPort":      hostPort,
								"containerPort": containerPort,
								"protocol":      "tcp",
							},
						},
					},
				}
				configList := makeConfig(ver)

				// Make delete idempotent, so we can clean up on failure
				netDeleted := false
				deleteNetwork := func() error {
					if netDeleted {
						return nil
					}
					netDeleted = true
					return cniConf.DelNetworkList(context.TODO(), configList, &runtimeConfig)
				}

				// we'll also manually check the iptables chains
				ipt, err := iptables.NewWithProtocol(iptables.ProtocolIPv4)
				Expect(err).NotTo(HaveOccurred())
				dnatChainName := genDnatChain("cni-portmap-unit-test", runtimeConfig.ContainerID).name

				// Create the network
				resI, err := cniConf.AddNetworkList(context.TODO(), configList, &runtimeConfig)
				Expect(err).NotTo(HaveOccurred())
				defer deleteNetwork()

				// Undo Docker's forwarding policy
				cmd := exec.Command("iptables", "-t", "filter",
					"-P", "FORWARD", "ACCEPT")
				cmd.Stderr = GinkgoWriter
				err = cmd.Run()
				Expect(err).NotTo(HaveOccurred())

				// Check the chain exists
				_, err = ipt.List("nat", dnatChainName)
				Expect(err).NotTo(HaveOccurred())

				result, err := types100.GetResult(resI)
				Expect(err).NotTo(HaveOccurred())
				var contIP net.IP

				for _, ip := range result.IPs {
					intfIndex := *ip.Interface
					if result.Interfaces[intfIndex].Sandbox == "" {
						continue
					}
					contIP = ip.Address.IP
				}
				if contIP == nil {
					Fail("could not determine container IP")
				}

				hostIP := getLocalIP()
				fmt.Fprintf(GinkgoWriter, "hostIP: %s:%d, contIP: %s:%d\n",
					hostIP, hostPort, contIP, containerPort)

				// dump iptables-save output for debugging
				cmd = exec.Command("iptables-save")
				cmd.Stderr = GinkgoWriter
				cmd.Stdout = GinkgoWriter
				Expect(cmd.Run()).To(Succeed())

				// dump ip routes output for debugging
				cmd = exec.Command("ip", "route")
				cmd.Stderr = GinkgoWriter
				cmd.Stdout = GinkgoWriter
				Expect(cmd.Run()).To(Succeed())

				// dump ip addresses output for debugging
				cmd = exec.Command("ip", "addr")
				cmd.Stderr = GinkgoWriter
				cmd.Stdout = GinkgoWriter
				Expect(cmd.Run()).To(Succeed())

				// Sanity check: verify that the container is reachable directly
				contOK := testEchoServer(contIP.String(), "tcp", containerPort, "")

				// Verify that a connection to the forwarded port works
				dnatOK := testEchoServer(hostIP, "tcp", hostPort, "")

				// Verify that a connection to localhost works
				snatOK := testEchoServer("127.0.0.1", "tcp", hostPort, "")

				// verify that hairpin works
				hairpinOK := testEchoServer(hostIP, "tcp", hostPort, targetNS.Path())

				// Cleanup
				session.Terminate()
				err = deleteNetwork()
				Expect(err).NotTo(HaveOccurred())

				// Verify iptables rules are gone
				_, err = ipt.List("nat", dnatChainName)
				Expect(err).To(HaveOccurred())

				// Check that everything succeeded *after* we clean up the network
				if !contOK {
					Fail("connection direct to " + contIP.String() + " failed")
				}
				if !dnatOK {
					Fail("Connection to " + hostIP + " was not forwarded")
				}
				if !snatOK {
					Fail("connection to 127.0.0.1 was not forwarded")
				}
				if !hairpinOK {
					Fail("Hairpin connection failed")
				}

				close(done)
			})

			It(fmt.Sprintf("[%s] forwards a UDP port on ipv4 and keep working after creating a second container with the same HostPort", ver), func(done Done) {
				var err error
				hostPort := rand.Intn(10000) + 1025
				runtimeConfig := libcni.RuntimeConf{
					ContainerID: fmt.Sprintf("unit-test-%d", hostPort),
					NetNS:       targetNS.Path(),
					IfName:      "eth0",
					CapabilityArgs: map[string]interface{}{
						"portMappings": []map[string]interface{}{
							{
								"hostPort":      hostPort,
								"containerPort": containerPort,
								"protocol":      "udp",
							},
						},
					},
				}
				configList := makeConfig(ver)

				// Make delete idempotent, so we can clean up on failure
				netDeleted := false
				deleteNetwork := func() error {
					if netDeleted {
						return nil
					}
					netDeleted = true
					return cniConf.DelNetworkList(context.TODO(), configList, &runtimeConfig)
				}

				// Create the network
				resI, err := cniConf.AddNetworkList(context.TODO(), configList, &runtimeConfig)
				Expect(err).NotTo(HaveOccurred())
				defer deleteNetwork()

				// Undo Docker's forwarding policy
				cmd := exec.Command("iptables", "-t", "filter",
					"-P", "FORWARD", "ACCEPT")
				cmd.Stderr = GinkgoWriter
				err = cmd.Run()
				Expect(err).NotTo(HaveOccurred())

				result, err := types100.GetResult(resI)
				Expect(err).NotTo(HaveOccurred())
				var contIP net.IP

				for _, ip := range result.IPs {
					intfIndex := *ip.Interface
					if result.Interfaces[intfIndex].Sandbox == "" {
						continue
					}
					contIP = ip.Address.IP
				}
				if contIP == nil {
					Fail("could not determine container IP")
				}

				hostIP := getLocalIP()
				fmt.Fprintf(GinkgoWriter, "First container hostIP: %s:%d, contIP: %s:%d\n",
					hostIP, hostPort, contIP, containerPort)

				// dump iptables-save output for debugging
				cmd = exec.Command("iptables-save")
				cmd.Stderr = GinkgoWriter
				cmd.Stdout = GinkgoWriter
				Expect(cmd.Run()).To(Succeed())

				// dump ip routes output for debugging
				cmd = exec.Command("ip", "route")
				cmd.Stderr = GinkgoWriter
				cmd.Stdout = GinkgoWriter
				Expect(cmd.Run()).To(Succeed())

				// dump ip addresses output for debugging
				cmd = exec.Command("ip", "addr")
				cmd.Stderr = GinkgoWriter
				cmd.Stdout = GinkgoWriter
				Expect(cmd.Run()).To(Succeed())

				// Sanity check: verify that the container is reachable directly
				fmt.Fprintln(GinkgoWriter, "Connect to container:", contIP.String(), containerPort)
				contOK := testEchoServer(contIP.String(), "udp", containerPort, "")

				// Verify that a connection to the forwarded port works
				fmt.Fprintln(GinkgoWriter, "Connect to host:", hostIP, hostPort)
				dnatOK := testEchoServer(hostIP, "udp", hostPort, "")

				// Cleanup
				session.Terminate()
				err = deleteNetwork()
				Expect(err).NotTo(HaveOccurred())

				// Check that everything succeeded *after* we clean up the network
				if !contOK {
					Fail("connection direct to " + contIP.String() + " failed")
				}
				if !dnatOK {
					Fail("Connection to " + hostIP + " was not forwarded")
				}
				// Create a second container
				targetNS2, err := testutils.NewNS()
				Expect(err).NotTo(HaveOccurred())
				fmt.Fprintln(GinkgoWriter, "namespace:", targetNS2.Path())

				// Start an echo server and get the port
				containerPort, session2 := StartEchoServerInNamespace(targetNS2)

				runtimeConfig2 := libcni.RuntimeConf{
					ContainerID: fmt.Sprintf("unit-test2-%d", hostPort),
					NetNS:       targetNS2.Path(),
					IfName:      "eth0",
					CapabilityArgs: map[string]interface{}{
						"portMappings": []map[string]interface{}{
							{
								"hostPort":      hostPort,
								"containerPort": containerPort,
								"protocol":      "udp",
							},
						},
					},
				}

				// Make delete idempotent, so we can clean up on failure
				net2Deleted := false
				deleteNetwork2 := func() error {
					if net2Deleted {
						return nil
					}
					net2Deleted = true
					return cniConf.DelNetworkList(context.TODO(), configList, &runtimeConfig2)
				}

				// Create the network
				resI2, err := cniConf.AddNetworkList(context.TODO(), configList, &runtimeConfig2)
				Expect(err).NotTo(HaveOccurred())
				defer deleteNetwork2()

				result2, err := types100.GetResult(resI2)
				Expect(err).NotTo(HaveOccurred())
				var contIP2 net.IP

				for _, ip := range result2.IPs {
					intfIndex := *ip.Interface
					if result2.Interfaces[intfIndex].Sandbox == "" {
						continue
					}
					contIP2 = ip.Address.IP
				}
				if contIP2 == nil {
					Fail("could not determine container IP")
				}

				fmt.Fprintf(GinkgoWriter, "Second container: hostIP: %s:%d, contIP: %s:%d\n",
					hostIP, hostPort, contIP2, containerPort)

				// dump iptables-save output for debugging
				cmd = exec.Command("iptables-save")
				cmd.Stderr = GinkgoWriter
				cmd.Stdout = GinkgoWriter
				Expect(cmd.Run()).To(Succeed())

				// dump ip routes output for debugging
				cmd = exec.Command("ip", "route")
				cmd.Stderr = GinkgoWriter
				cmd.Stdout = GinkgoWriter
				Expect(cmd.Run()).To(Succeed())

				// dump ip addresses output for debugging
				cmd = exec.Command("ip", "addr")
				cmd.Stderr = GinkgoWriter
				cmd.Stdout = GinkgoWriter
				Expect(cmd.Run()).To(Succeed())

				// Sanity check: verify that the container is reachable directly
				fmt.Fprintln(GinkgoWriter, "Connect to container:", contIP2.String(), containerPort)
				cont2OK := testEchoServer(contIP2.String(), "udp", containerPort, "")

				// Verify that a connection to the forwarded port works
				fmt.Fprintln(GinkgoWriter, "Connect to host:", hostIP, hostPort)
				dnat2OK := testEchoServer(hostIP, "udp", hostPort, "")

				// Cleanup
				session2.Terminate()
				err = deleteNetwork2()
				Expect(err).NotTo(HaveOccurred())

				// Check that everything succeeded *after* we clean up the network
				if !cont2OK {
					Fail("connection direct to " + contIP2.String() + " failed")
				}
				if !dnat2OK {
					Fail("Connection to " + hostIP + " was not forwarded")
				}

				close(done)
			})
		})
	}
})

// testEchoServer returns true if we found an echo server on the port
func testEchoServer(address, protocol string, port int, netns string) bool {
	message := "'Aliquid melius quam pessimum optimum non est.'"

	var cmd *exec.Cmd
	if netns != "" {
		netns = filepath.Base(netns)
		cmd = exec.Command("ip", "netns", "exec", netns, echoClientBinaryPath, "--target", fmt.Sprintf("%s:%d", address, port), "--message", message, "--protocol", protocol)
	} else {
		cmd = exec.Command(echoClientBinaryPath, "--target", fmt.Sprintf("%s:%d", address, port), "--message", message, "--protocol", protocol)
	}
	cmd.Stdin = bytes.NewBufferString(message)
	cmd.Stderr = GinkgoWriter
	out, err := cmd.Output()
	if err != nil {
		fmt.Fprintln(GinkgoWriter, "got non-zero exit from ", cmd.Args)
		return false
	}

	if string(out) != message {
		fmt.Fprintln(GinkgoWriter, "returned message didn't match?")
		fmt.Fprintln(GinkgoWriter, string(out))
		return false
	}

	return true
}

func getLocalIP() string {
	addrs, err := netlink.AddrList(nil, netlink.FAMILY_V4)
	Expect(err).NotTo(HaveOccurred())

	for _, addr := range addrs {
		if !addr.IP.IsGlobalUnicast() {
			continue
		}
		return addr.IP.String()
	}
	Fail("no live addresses")
	return ""
}
