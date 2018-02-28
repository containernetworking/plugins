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
package integration_test

import (
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gexec"
)

var _ = Describe("Basic PTP using cnitool", func() {
	var (
		env        TestEnv
		hostNS     NSShortName
		contNS     NSShortName
		cnitoolBin string
	)

	BeforeEach(func() {
		cniPath, err := filepath.Abs("../bin")
		Expect(err).NotTo(HaveOccurred())
		netConfPath, err := filepath.Abs("./testdata")
		Expect(err).NotTo(HaveOccurred())
		cnitoolBin, err = exec.LookPath("cnitool")
		Expect(err).NotTo(HaveOccurred(), "expected to find cnitool in your PATH")

		env = TestEnv([]string{
			"CNI_PATH=" + cniPath,
			"NETCONFPATH=" + netConfPath,
			"PATH=" + os.Getenv("PATH"),
		})

		hostNS = NSShortName(fmt.Sprintf("cni-test-host-%x", rand.Int31()))
		hostNS.Add()

		contNS = NSShortName(fmt.Sprintf("cni-test-cont-%x", rand.Int31()))
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

	It("supports add and del with bridge + bandwidth", func() {
		basicAssertion("chained-bridge-bandwidth", "10.11.2.")
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

func (e TestEnv) runInNS(nsShortName NSShortName, bin string, args ...string) string {
	a := append([]string{"netns", "exec", string(nsShortName), bin}, args...)
	return e.run("ip", a...)
}

type NSShortName string

func (n NSShortName) LongName() string {
	return fmt.Sprintf("/var/run/netns/%s", n)
}

func (n NSShortName) Add() {
	(TestEnv{}).run("ip", "netns", "add", string(n))
}

func (n NSShortName) Del() {
	(TestEnv{}).run("ip", "netns", "del", string(n))
}
