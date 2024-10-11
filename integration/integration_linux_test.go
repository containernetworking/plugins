// Copyright 2018 CNI authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package integration_test

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gbytes"
	"github.com/onsi/gomega/gexec"
)

var _ = Describe("Basic PTP using cnitool", func() {
	var (
		cnitoolBin string
		cniPath    string
	)

	BeforeEach(func() {
		var err error
		cniPath, err = filepath.Abs("../bin")
		Expect(err).NotTo(HaveOccurred())
		cnitoolBin, err = exec.LookPath("cnitool")
		Expect(err).NotTo(HaveOccurred(), "expected to find cnitool in your PATH")
	})

	Context("basic cases", func() {
		var (
			env    TestEnv
			hostNS Namespace
			contNS Namespace
		)

		BeforeEach(func() {
			var err error

			netConfPath, err := filepath.Abs("./testdata")
			Expect(err).NotTo(HaveOccurred())

			// Flush ipam stores to avoid conflicts
			err = os.RemoveAll("/tmp/chained-ptp-bandwidth-test")
			Expect(err).NotTo(HaveOccurred())

			err = os.RemoveAll("/tmp/basic-ptp-test")
			Expect(err).NotTo(HaveOccurred())

			env = TestEnv([]string{
				"CNI_PATH=" + cniPath,
				"NETCONFPATH=" + netConfPath,
				"PATH=" + os.Getenv("PATH"),
			})

			hostNS = Namespace(fmt.Sprintf("cni-test-host-%x", rand.Int31()))
			hostNS.Add()

			contNS = Namespace(fmt.Sprintf("cni-test-cont-%x", rand.Int31()))
			contNS.Add()
		})

		AfterEach(func() {
			contNS.Del()
			hostNS.Del()
		})

		basicAssertion := func(netName, expectedIPPrefix string) {
			env.runInNS(hostNS, cnitoolBin, "add", netName, contNS.LongName())

			addrOutput := env.runInNS(contNS, "ip", "addr")

			Expect(addrOutput).To(ContainSubstring(expectedIPPrefix))

			env.runInNS(hostNS, cnitoolBin, "del", netName, contNS.LongName())
		}

		It("supports basic network add and del operations", func() {
			basicAssertion("basic-ptp", "10.1.2.")
		})

		It("supports add and del with ptp + bandwidth", func() {
			basicAssertion("chained-ptp-bandwidth", "10.9.2.")
		})
	})

	Context("when the bandwidth plugin is chained with a plugin that returns multiple adapters", func() {
		var (
			hostNS                                            Namespace
			contNS1                                           Namespace
			contNS2                                           Namespace
			basicBridgeEnv                                    TestEnv
			chainedBridgeBandwidthEnv                         TestEnv
			chainedBridgeBandwidthSession, basicBridgeSession *gexec.Session
		)

		BeforeEach(func() {
			hostNS = Namespace(fmt.Sprintf("cni-test-host-%x", rand.Int31()))
			hostNS.Add()

			contNS1 = Namespace(fmt.Sprintf("cni-test-cont1-%x", rand.Int31()))
			contNS1.Add()

			contNS2 = Namespace(fmt.Sprintf("cni-test-cont2-%x", rand.Int31()))
			contNS2.Add()

			basicBridgeNetConfPath, err := filepath.Abs("./testdata/basic-bridge")
			Expect(err).NotTo(HaveOccurred())

			basicBridgeEnv = TestEnv([]string{
				"CNI_PATH=" + cniPath,
				"NETCONFPATH=" + basicBridgeNetConfPath,
				"PATH=" + os.Getenv("PATH"),
			})

			chainedBridgeBandwidthNetConfPath, err := filepath.Abs("./testdata/chained-bridge-bandwidth")
			Expect(err).NotTo(HaveOccurred())

			chainedBridgeBandwidthEnv = TestEnv([]string{
				"CNI_PATH=" + cniPath,
				"NETCONFPATH=" + chainedBridgeBandwidthNetConfPath,
				"PATH=" + os.Getenv("PATH"),
			})
		})

		AfterEach(func() {
			if chainedBridgeBandwidthSession != nil {
				chainedBridgeBandwidthSession.Kill()
			}
			if basicBridgeSession != nil {
				basicBridgeSession.Kill()
			}

			chainedBridgeBandwidthEnv.runInNS(hostNS, cnitoolBin, "del", "network-chain-test", contNS1.LongName())
			basicBridgeEnv.runInNS(hostNS, cnitoolBin, "del", "network-chain-test", contNS2.LongName())

			contNS1.Del()
			contNS2.Del()
			hostNS.Del()
		})

		It("limits traffic only on the restricted bandwidth veth device", func() {
			ipRegexp := regexp.MustCompile(`10\.1[12]\.2\.\d{1,3}`)

			By(fmt.Sprintf("adding %s to %s\n\n", "chained-bridge-bandwidth", contNS1.ShortName()))
			chainedBridgeBandwidthEnv.runInNS(hostNS, cnitoolBin, "add", "network-chain-test", contNS1.LongName())
			chainedBridgeIP := ipRegexp.FindString(chainedBridgeBandwidthEnv.runInNS(contNS1, "ip", "addr"))
			Expect(chainedBridgeIP).To(ContainSubstring("10.12.2."))

			By(fmt.Sprintf("adding %s to %s\n\n", "basic-bridge", contNS2.ShortName()))
			basicBridgeEnv.runInNS(hostNS, cnitoolBin, "add", "network-chain-test", contNS2.LongName())
			basicBridgeIP := ipRegexp.FindString(basicBridgeEnv.runInNS(contNS2, "ip", "addr"))
			Expect(basicBridgeIP).To(ContainSubstring("10.11.2."))

			var chainedBridgeBandwidthPort, basicBridgePort int

			By(fmt.Sprintf("starting echo server in %s\n\n", contNS1.ShortName()))
			chainedBridgeBandwidthPort, chainedBridgeBandwidthSession = startEchoServerInNamespace(contNS1)

			By(fmt.Sprintf("starting echo server in %s\n\n", contNS2.ShortName()))
			basicBridgePort, basicBridgeSession = startEchoServerInNamespace(contNS2)

			packetInBytes := 20000 // The shaper needs to 'warm'. Send enough to cause it to throttle,
			// balanced by run time.

			By(fmt.Sprintf("sending tcp traffic to the chained, bridged, traffic shaped container on ip address '%s:%d'\n\n", chainedBridgeIP, chainedBridgeBandwidthPort))
			start := time.Now()
			makeTCPClientInNS(hostNS.ShortName(), chainedBridgeIP, chainedBridgeBandwidthPort, packetInBytes)
			runtimeWithLimit := time.Since(start)
			log.Printf("Runtime with qos limit %.2f seconds", runtimeWithLimit.Seconds())

			By(fmt.Sprintf("sending tcp traffic to the basic bridged container on ip address '%s:%d'\n\n", basicBridgeIP, basicBridgePort))
			start = time.Now()
			makeTCPClientInNS(hostNS.ShortName(), basicBridgeIP, basicBridgePort, packetInBytes)
			runtimeWithoutLimit := time.Since(start)
			log.Printf("Runtime without qos limit %.2f seconds", runtimeWithoutLimit.Seconds())

			Expect(runtimeWithLimit).To(BeNumerically(">", runtimeWithoutLimit+1000*time.Millisecond))
		})
	})
})

type TestEnv []string

func (e TestEnv) run(bin string, args ...string) string {
	cmd := exec.Command(bin, args...)
	cmd.Env = e
	session, err := gexec.Start(cmd, GinkgoWriter, GinkgoWriter)
	Expect(err).NotTo(HaveOccurred())
	Eventually(session, "5s").Should(gexec.Exit(0))
	return string(session.Out.Contents())
}

func (e TestEnv) runInNS(nsShortName Namespace, bin string, args ...string) string {
	a := append([]string{"netns", "exec", string(nsShortName), bin}, args...)
	return e.run("ip", a...)
}

type Namespace string

func (n Namespace) LongName() string {
	return fmt.Sprintf("/var/run/netns/%s", n)
}

func (n Namespace) ShortName() string {
	return string(n)
}

func (n Namespace) Add() {
	(TestEnv{}).run("ip", "netns", "add", string(n))
}

func (n Namespace) Del() {
	(TestEnv{}).run("ip", "netns", "del", string(n))
}

func makeTCPClientInNS(netns string, address string, port int, numBytes int) {
	payload := bytes.Repeat([]byte{'a'}, numBytes)
	message := string(payload)

	var cmd *exec.Cmd
	if netns != "" {
		netns = filepath.Base(netns)
		cmd = exec.Command("ip", "netns", "exec", netns, echoClientBinaryPath, "--target", fmt.Sprintf("%s:%d", address, port), "--message", message)
	} else {
		cmd = exec.Command(echoClientBinaryPath, "--target", fmt.Sprintf("%s:%d", address, port), "--message", message)
	}
	cmd.Stdin = bytes.NewBuffer([]byte(message))
	cmd.Stderr = GinkgoWriter
	out, err := cmd.Output()

	Expect(err).NotTo(HaveOccurred())
	Expect(string(out)).To(Equal(message))
}

func startEchoServerInNamespace(netNS Namespace) (int, *gexec.Session) {
	session, err := startInNetNS(echoServerBinaryPath, netNS)
	Expect(err).NotTo(HaveOccurred())

	// wait for it to print it's address on stdout
	Eventually(session.Out).Should(gbytes.Say("\n"))
	_, portString, err := net.SplitHostPort(strings.TrimSpace(string(session.Out.Contents())))
	Expect(err).NotTo(HaveOccurred())

	port, err := strconv.Atoi(portString)
	Expect(err).NotTo(HaveOccurred())

	go func() {
		// print out echoserver output to ginkgo to capture any errors that might be occurring.
		io.Copy(GinkgoWriter, io.MultiReader(session.Out, session.Err))
	}()

	return port, session
}

func startInNetNS(binPath string, namespace Namespace) (*gexec.Session, error) {
	cmd := exec.Command("ip", "netns", "exec", namespace.ShortName(), binPath)
	return gexec.Start(cmd, GinkgoWriter, GinkgoWriter)
}
