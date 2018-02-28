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
		env         TestEnv
		nsShortName string
		nsLongName  string
		cnitoolBin  string
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

		nsShortName = fmt.Sprintf("cni-test-%x", rand.Int31())
		nsLongName = fmt.Sprintf("/var/run/netns/" + nsShortName)
	})

	It("supports basic network add and del operations", func() {
		env.run("ip", "netns", "add", nsShortName)
		defer env.run("ip", "netns", "del", nsShortName)

		env.run(cnitoolBin, "add", "basic-ptp", nsLongName)

		addrOutput := env.run("ip", "netns", "exec", nsShortName, "ip", "addr")
		Expect(addrOutput).To(ContainSubstring("10.1.2."))

		env.run(cnitoolBin, "del", "basic-ptp", nsLongName)
	})

	It("supports add and del with chained plugins", func() {
		env.run("ip", "netns", "add", nsShortName)
		defer env.run("ip", "netns", "del", nsShortName)

		env.run(cnitoolBin, "add", "chained-ptp-bandwidth", nsLongName)

		addrOutput := env.run("ip", "netns", "exec", nsShortName, "ip", "addr")
		Expect(addrOutput).To(ContainSubstring("10.9.2."))

		env.run(cnitoolBin, "del", "chained-ptp-bandwidth", nsLongName)
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
