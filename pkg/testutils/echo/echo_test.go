package main_test

import (
	"fmt"
	"io"
	"net"
	"os/exec"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gbytes"
	"github.com/onsi/gomega/gexec"
)

var serverBinaryPath, clientBinaryPath string

var _ = SynchronizedBeforeSuite(func() []byte {
	serverBinaryPath, err := gexec.Build("github.com/containernetworking/plugins/pkg/testutils/echo/server")
	Expect(err).NotTo(HaveOccurred())
	clientBinaryPath, err := gexec.Build("github.com/containernetworking/plugins/pkg/testutils/echo/client")
	Expect(err).NotTo(HaveOccurred())
	return []byte(strings.Join([]string{serverBinaryPath, clientBinaryPath}, ","))
}, func(data []byte) {
	binaries := strings.Split(string(data), ",")
	serverBinaryPath = binaries[0]
	clientBinaryPath = binaries[1]
})

var _ = SynchronizedAfterSuite(func() {}, func() {
	gexec.CleanupBuildArtifacts()
})

var _ = Describe("Echosvr", func() {
	var session *gexec.Session
	BeforeEach(func() {
		var err error
		cmd := exec.Command(serverBinaryPath)
		session, err = gexec.Start(cmd, GinkgoWriter, GinkgoWriter)
		Expect(err).NotTo(HaveOccurred())
	})

	AfterEach(func() {
		session.Kill().Wait()
	})

	Context("Server test", func() {
		It("starts and doesn't terminate immediately", func() {
			Consistently(session).ShouldNot(gexec.Exit())
		})

		tryConnect := func() (net.Conn, error) {
			programOutput := session.Out.Contents()
			addr := strings.TrimSpace(string(programOutput))

			conn, err := net.Dial("tcp", addr)
			if err != nil {
				return nil, err
			}
			return conn, err
		}

		It("prints its listening address to stdout", func() {
			Eventually(session.Out).Should(gbytes.Say("\n"))
			conn, err := tryConnect()
			Expect(err).NotTo(HaveOccurred())
			conn.Close()
		})

		It("will echo data back to us", func() {
			Eventually(session.Out).Should(gbytes.Say("\n"))
			conn, err := tryConnect()
			Expect(err).NotTo(HaveOccurred())
			defer conn.Close()

			fmt.Fprintf(conn, "hello\n")
			Expect(io.ReadAll(conn)).To(Equal([]byte("hello")))
		})
	})

	Context("Client Server Test", func() {
		It("starts and doesn't terminate immediately", func() {
			Consistently(session).ShouldNot(gexec.Exit())
		})

		It("connects successfully using echo client", func() {
			Eventually(session.Out).Should(gbytes.Say("\n"))
			serverAddress := strings.TrimSpace(string(session.Out.Contents()))
			fmt.Println("Server address", serverAddress)

			cmd := exec.Command(clientBinaryPath, "-target", serverAddress, "-message", "hello")
			clientSession, err := gexec.Start(cmd, GinkgoWriter, GinkgoWriter)
			Expect(err).NotTo(HaveOccurred())
			Eventually(clientSession.Out).Should(gbytes.Say("hello"))
			Eventually(clientSession).Should(gexec.Exit())
		})
	})
})
