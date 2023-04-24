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
	"net"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gbytes"
	"github.com/onsi/gomega/gexec"

	"github.com/containernetworking/plugins/pkg/ns"
)

func TestPortmap(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "plugins/meta/portmap")
}

var echoServerBinaryPath, echoClientBinaryPath string

var _ = SynchronizedBeforeSuite(func() []byte {
	serverBinaryPath, err := gexec.Build("github.com/containernetworking/plugins/pkg/testutils/echo/server")
	Expect(err).NotTo(HaveOccurred())
	clientBinaryPath, err := gexec.Build("github.com/containernetworking/plugins/pkg/testutils/echo/client")
	Expect(err).NotTo(HaveOccurred())
	return []byte(strings.Join([]string{serverBinaryPath, clientBinaryPath}, ","))
}, func(data []byte) {
	binaries := strings.Split(string(data), ",")
	echoServerBinaryPath = binaries[0]
	echoClientBinaryPath = binaries[1]
})

var _ = SynchronizedAfterSuite(func() {}, func() {
	gexec.CleanupBuildArtifacts()
})

func startInNetNS(binPath string, netNS ns.NetNS) (*gexec.Session, error) {
	baseName := filepath.Base(netNS.Path())
	// we are relying on the netNS path living in /var/run/netns
	// where `ip netns exec` can find it
	cmd := exec.Command("ip", "netns", "exec", baseName, binPath)
	session, err := gexec.Start(cmd, GinkgoWriter, GinkgoWriter)
	return session, err
}

func StartEchoServerInNamespace(netNS ns.NetNS) (int, *gexec.Session) {
	session, err := startInNetNS(echoServerBinaryPath, netNS)
	Expect(err).NotTo(HaveOccurred())

	// wait for it to print it's address on stdout
	Eventually(session.Out).Should(gbytes.Say("\n"))
	_, portString, err := net.SplitHostPort(strings.TrimSpace(string(session.Out.Contents())))
	Expect(err).NotTo(HaveOccurred())

	port, err := strconv.Atoi(portString)
	Expect(err).NotTo(HaveOccurred())
	return port, session
}
