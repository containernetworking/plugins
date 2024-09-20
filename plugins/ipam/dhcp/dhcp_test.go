// Copyright 2015-2018 CNI authors
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
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/vishvananda/netlink"

	"github.com/containernetworking/cni/pkg/skel"
	types100 "github.com/containernetworking/cni/pkg/types/100"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/containernetworking/plugins/pkg/testutils"
)

func getTmpDir() (string, error) {
	tmpDir, err := os.MkdirTemp(cniDirPrefix, "dhcp")
	if err == nil {
		tmpDir = filepath.ToSlash(tmpDir)
	}

	return tmpDir, err
}

type DhcpServer struct {
	cmd  *exec.Cmd
	lock sync.Mutex

	startAddr net.IP
	endAddr   net.IP
	leaseTime time.Duration
}

func (s *DhcpServer) Serve() error {
	if err := s.Start(); err != nil {
		return err
	}
	return s.cmd.Wait()
}

func (s *DhcpServer) Start() error {
	s.lock.Lock()
	defer s.lock.Unlock()

	s.cmd = exec.Command(
		"dnsmasq",
		"--no-daemon",
		"--dhcp-sequential-ip", // allocate IPs sequentially
		"--port=0",             // disable DNS
		"--conf-file=-",        // Do not read /etc/dnsmasq.conf
		fmt.Sprintf("--dhcp-range=%s,%s,%d", s.startAddr, s.endAddr, int(s.leaseTime.Seconds())),
	)
	s.cmd.Stdin = bytes.NewBufferString("")
	s.cmd.Stdout = os.Stdout
	s.cmd.Stderr = os.Stderr

	return s.cmd.Start()
}

func (s *DhcpServer) Stop() error {
	s.lock.Lock()
	defer s.lock.Unlock()
	return s.cmd.Process.Kill()
}

func dhcpServerStart(netns ns.NetNS, numLeases int, stopCh <-chan bool) *sync.WaitGroup {
	dhcpServer := &DhcpServer{
		startAddr: net.IPv4(192, 168, 1, 5),
		endAddr:   net.IPv4(192, 168, 1, 5+uint8(numLeases)-1),
		leaseTime: 5 * time.Minute,
	}

	stopWg := sync.WaitGroup{}
	stopWg.Add(2)
	startWg := sync.WaitGroup{}
	startWg.Add(2)

	// Run DHCP server in a goroutine so it doesn't block the main thread
	go func() {
		defer GinkgoRecover()

		err := netns.Do(func(ns.NetNS) error {
			startWg.Done()

			if err := dhcpServer.Serve(); err != nil {
				// Log, but don't trap errors; the server will
				// always report an error when stopped
				GinkgoT().Logf("DHCP server finished with error: %v", err)
			}
			return nil
		})
		stopWg.Done()
		// Trap any errors after the Done, to allow the main test thread
		// to continue and clean up.  Otherwise the test hangs.
		Expect(err).NotTo(HaveOccurred())
	}()

	// Stop DHCP server in another goroutine for the same reason
	go func() {
		startWg.Done()
		<-stopCh
		dhcpServer.Stop()
		stopWg.Done()
	}()
	startWg.Wait()

	return &stopWg
}

const (
	hostVethName string = "dhcp0"
	contVethName string = "eth0"
	cniDirPrefix string = "/var/run/cni"
)

var _ = BeforeSuite(func() {
	err := os.MkdirAll(cniDirPrefix, 0o700)
	Expect(err).NotTo(HaveOccurred())
})

var _ = Describe("DHCP Operations", func() {
	var originalNS, targetNS ns.NetNS
	var dhcpServerStopCh chan bool
	var dhcpServerDone *sync.WaitGroup
	var clientCmd *exec.Cmd
	var socketPath string
	var tmpDir string
	var err error

	BeforeEach(func() {
		dhcpServerStopCh = make(chan bool)

		tmpDir, err = getTmpDir()
		Expect(err).NotTo(HaveOccurred())
		socketPath = filepath.Join(tmpDir, "dhcp.sock")

		// Create a new NetNS so we don't modify the host
		var err error
		originalNS, err = testutils.NewNS()
		Expect(err).NotTo(HaveOccurred())

		targetNS, err = testutils.NewNS()
		Expect(err).NotTo(HaveOccurred())

		serverIP := net.IPNet{
			IP:   net.IPv4(192, 168, 1, 1),
			Mask: net.IPv4Mask(255, 255, 255, 0),
		}

		// Create a veth pair in the "host" (original) NS
		err = originalNS.Do(func(ns.NetNS) error {
			defer GinkgoRecover()

			linkAttrs := netlink.NewLinkAttrs()
			linkAttrs.Name = hostVethName
			err = netlink.LinkAdd(&netlink.Veth{
				LinkAttrs: linkAttrs,
				PeerName:  contVethName,
			})
			Expect(err).NotTo(HaveOccurred())

			host, err := netlink.LinkByName(hostVethName)
			Expect(err).NotTo(HaveOccurred())
			err = netlink.LinkSetUp(host)
			Expect(err).NotTo(HaveOccurred())
			err = netlink.AddrAdd(host, &netlink.Addr{IPNet: &serverIP})
			Expect(err).NotTo(HaveOccurred())
			err = netlink.RouteAdd(&netlink.Route{
				LinkIndex: host.Attrs().Index,
				Scope:     netlink.SCOPE_UNIVERSE,
				Dst: &net.IPNet{
					IP:   net.IPv4(0, 0, 0, 0),
					Mask: net.IPv4Mask(0, 0, 0, 0),
				},
			})
			Expect(err).NotTo(HaveOccurred())

			cont, err := netlink.LinkByName(contVethName)
			Expect(err).NotTo(HaveOccurred())
			err = netlink.LinkSetNsFd(cont, int(targetNS.Fd()))
			Expect(err).NotTo(HaveOccurred())

			return nil
		})
		Expect(err).NotTo(HaveOccurred())

		// Move the container side to the container's NS
		err = targetNS.Do(func(_ ns.NetNS) error {
			defer GinkgoRecover()

			link, err := netlink.LinkByName(contVethName)
			Expect(err).NotTo(HaveOccurred())
			err = netlink.LinkSetUp(link)
			Expect(err).NotTo(HaveOccurred())
			return nil
		})

		// Start the DHCP server
		dhcpServerDone = dhcpServerStart(originalNS, 1, dhcpServerStopCh)

		// Start the DHCP client daemon
		dhcpPluginPath, err := exec.LookPath("dhcp")
		Expect(err).NotTo(HaveOccurred())
		clientCmd = exec.Command(dhcpPluginPath, "daemon", "-socketpath", socketPath)

		// copy dhcp client's stdout/stderr to test stdout
		clientCmd.Stdout = os.Stdout
		clientCmd.Stderr = os.Stderr

		err = clientCmd.Start()
		Expect(err).NotTo(HaveOccurred())
		Expect(clientCmd.Process).NotTo(BeNil())

		// Wait up to 15 seconds for the client socket
		Eventually(func() bool {
			_, err := os.Stat(socketPath)
			return err == nil
		}, time.Second*15, time.Second/4).Should(BeTrue())
	})

	AfterEach(func() {
		dhcpServerStopCh <- true
		dhcpServerDone.Wait()
		clientCmd.Process.Kill()
		clientCmd.Wait()

		Expect(originalNS.Close()).To(Succeed())
		Expect(testutils.UnmountNS(originalNS)).To(Succeed())
		Expect(targetNS.Close()).To(Succeed())
		Expect(testutils.UnmountNS(targetNS)).To(Succeed())

		Expect(os.RemoveAll(tmpDir)).To(Succeed())
	})

	for _, ver := range testutils.AllSpecVersions {
		// Redefine ver inside for scope so real value is picked up by each dynamically defined It()
		// See Gingkgo's "Patterns for dynamically generating tests" documentation.
		ver := ver

		It(fmt.Sprintf("[%s] configures and deconfigures a link with ADD/DEL", ver), func() {
			conf := fmt.Sprintf(`{
			    "cniVersion": "%s",
			    "name": "mynet",
			    "type": "ipvlan",
			    "ipam": {
				"type": "dhcp",
				"daemonSocketPath": "%s"
			    }
			}`, ver, socketPath)

			args := &skel.CmdArgs{
				ContainerID: "dummy",
				Netns:       targetNS.Path(),
				IfName:      contVethName,
				StdinData:   []byte(conf),
			}

			var addResult *types100.Result
			err := originalNS.Do(func(ns.NetNS) error {
				defer GinkgoRecover()

				r, _, err := testutils.CmdAddWithArgs(args, func() error {
					return cmdAdd(args)
				})
				Expect(err).NotTo(HaveOccurred())

				addResult, err = types100.GetResult(r)
				Expect(err).NotTo(HaveOccurred())
				Expect(addResult.IPs).To(HaveLen(1))
				Expect(addResult.IPs[0].Address.String()).To(Equal("192.168.1.5/24"))
				return nil
			})
			Expect(err).NotTo(HaveOccurred())

			err = originalNS.Do(func(ns.NetNS) error {
				return testutils.CmdDelWithArgs(args, func() error {
					return cmdDel(args)
				})
			})
			Expect(err).NotTo(HaveOccurred())
		})

		It(fmt.Sprintf("[%s] correctly handles multiple DELs for the same container", ver), func() {
			conf := fmt.Sprintf(`{
			    "cniVersion": "%s",
			    "name": "mynet",
			    "type": "ipvlan",
			    "ipam": {
				"type": "dhcp",
				"daemonSocketPath": "%s"
			    }
			}`, ver, socketPath)

			args := &skel.CmdArgs{
				ContainerID: "dummy",
				Netns:       targetNS.Path(),
				IfName:      contVethName,
				StdinData:   []byte(conf),
			}

			var addResult *types100.Result
			err := originalNS.Do(func(ns.NetNS) error {
				defer GinkgoRecover()

				r, _, err := testutils.CmdAddWithArgs(args, func() error {
					return cmdAdd(args)
				})
				Expect(err).NotTo(HaveOccurred())

				addResult, err = types100.GetResult(r)
				Expect(err).NotTo(HaveOccurred())
				Expect(addResult.IPs).To(HaveLen(1))
				Expect(addResult.IPs[0].Address.String()).To(Equal("192.168.1.5/24"))
				return nil
			})
			Expect(err).NotTo(HaveOccurred())

			wg := sync.WaitGroup{}
			wg.Add(3)
			started := sync.WaitGroup{}
			started.Add(3)
			for i := 0; i < 3; i++ {
				go func() {
					defer GinkgoRecover()

					// Wait until all goroutines are running
					started.Done()
					started.Wait()

					err := originalNS.Do(func(ns.NetNS) error {
						return testutils.CmdDelWithArgs(args, func() error {
							copiedArgs := &skel.CmdArgs{
								ContainerID: args.ContainerID,
								Netns:       args.Netns,
								IfName:      args.IfName,
								StdinData:   args.StdinData,
								Path:        args.Path,
								Args:        args.Args,
							}
							return cmdDel(copiedArgs)
						})
					})
					Expect(err).NotTo(HaveOccurred())
					wg.Done()
				}()
			}
			wg.Wait()

			err = originalNS.Do(func(ns.NetNS) error {
				return testutils.CmdDelWithArgs(args, func() error {
					return cmdDel(args)
				})
			})
			Expect(err).NotTo(HaveOccurred())
		})
	}
})

const (
	hostBridgeName string = "dhcpbr0"
	hostVethName0  string = "br-eth0"
	contVethName0  string = "eth0"
	hostVethName1  string = "br-eth1"
	contVethName1  string = "eth1"
)

func dhcpSetupOriginalNS() (chan bool, string, ns.NetNS, ns.NetNS, error) {
	var originalNS, targetNS ns.NetNS
	var dhcpServerStopCh chan bool
	var socketPath string
	var br *netlink.Bridge
	var tmpDir string
	var err error

	dhcpServerStopCh = make(chan bool)

	tmpDir, err = getTmpDir()
	Expect(err).NotTo(HaveOccurred())
	socketPath = filepath.Join(tmpDir, "dhcp.sock")

	// Create a new NetNS so we don't modify the host
	originalNS, err = testutils.NewNS()
	Expect(err).NotTo(HaveOccurred())

	targetNS, err = testutils.NewNS()
	Expect(err).NotTo(HaveOccurred())

	// Use (original) NS
	err = originalNS.Do(func(ns.NetNS) error {
		defer GinkgoRecover()

		linkAttrs := netlink.NewLinkAttrs()
		linkAttrs.Name = hostBridgeName
		// Create bridge in the "host" (original) NS
		br = &netlink.Bridge{
			LinkAttrs: linkAttrs,
		}

		err = netlink.LinkAdd(br)
		Expect(err).NotTo(HaveOccurred())

		address := &netlink.Addr{IPNet: &net.IPNet{
			IP:   net.IPv4(192, 168, 1, 1),
			Mask: net.IPv4Mask(255, 255, 255, 0),
		}}
		err = netlink.AddrAdd(br, address)
		Expect(err).NotTo(HaveOccurred())

		err = netlink.LinkSetUp(br)
		Expect(err).NotTo(HaveOccurred())

		err = netlink.RouteAdd(&netlink.Route{
			LinkIndex: br.Attrs().Index,
			Scope:     netlink.SCOPE_UNIVERSE,
			Dst: &net.IPNet{
				IP:   net.IPv4(0, 0, 0, 0),
				Mask: net.IPv4Mask(0, 0, 0, 0),
			},
		})
		Expect(err).NotTo(HaveOccurred())

		// Create veth pair eth0
		vethLinkAttrs := netlink.NewLinkAttrs()
		vethLinkAttrs.Name = hostVethName0

		veth := &netlink.Veth{
			LinkAttrs: vethLinkAttrs,
			PeerName:  contVethName0,
		}
		err = netlink.LinkAdd(veth)
		Expect(err).NotTo(HaveOccurred())

		err = netlink.LinkSetUp(veth)
		Expect(err).NotTo(HaveOccurred())

		bridgeLink, err := netlink.LinkByName(hostBridgeName)
		Expect(err).NotTo(HaveOccurred())

		hostVethLink, err := netlink.LinkByName(hostVethName0)
		Expect(err).NotTo(HaveOccurred())

		err = netlink.LinkSetMaster(hostVethLink, bridgeLink.(*netlink.Bridge))
		Expect(err).NotTo(HaveOccurred())

		cont, err := netlink.LinkByName(contVethName0)
		Expect(err).NotTo(HaveOccurred())
		err = netlink.LinkSetNsFd(cont, int(targetNS.Fd()))
		Expect(err).NotTo(HaveOccurred())

		// Create veth path - eth1
		vethLinkAttrs1 := netlink.NewLinkAttrs()
		vethLinkAttrs1.Name = hostVethName1

		veth1 := &netlink.Veth{
			LinkAttrs: vethLinkAttrs1,
			PeerName:  contVethName1,
		}
		err = netlink.LinkAdd(veth1)
		Expect(err).NotTo(HaveOccurred())

		err = netlink.LinkSetUp(veth1)
		Expect(err).NotTo(HaveOccurred())

		bridgeLink, err = netlink.LinkByName(hostBridgeName)
		Expect(err).NotTo(HaveOccurred())

		hostVethLink1, err := netlink.LinkByName(hostVethName1)
		Expect(err).NotTo(HaveOccurred())

		err = netlink.LinkSetMaster(hostVethLink1, bridgeLink.(*netlink.Bridge))
		Expect(err).NotTo(HaveOccurred())

		cont1, err := netlink.LinkByName(contVethName1)
		Expect(err).NotTo(HaveOccurred())

		err = netlink.LinkSetNsFd(cont1, int(targetNS.Fd()))
		Expect(err).NotTo(HaveOccurred())

		return nil
	})

	return dhcpServerStopCh, socketPath, originalNS, targetNS, err
}

var _ = Describe("DHCP Lease Unavailable Operations", func() {
	var originalNS, targetNS ns.NetNS
	var dhcpServerStopCh chan bool
	var dhcpServerDone *sync.WaitGroup
	var clientCmd *exec.Cmd
	var socketPath string
	var tmpDir string
	var err error

	BeforeEach(func() {
		dhcpServerStopCh, socketPath, originalNS, targetNS, err = dhcpSetupOriginalNS()
		Expect(err).NotTo(HaveOccurred())

		// Move the container side to the container's NS
		err = targetNS.Do(func(_ ns.NetNS) error {
			defer GinkgoRecover()

			link, err := netlink.LinkByName(contVethName0)
			Expect(err).NotTo(HaveOccurred())
			err = netlink.LinkSetUp(link)
			Expect(err).NotTo(HaveOccurred())

			link1, err := netlink.LinkByName(contVethName1)
			Expect(err).NotTo(HaveOccurred())
			err = netlink.LinkSetUp(link1)
			Expect(err).NotTo(HaveOccurred())
			return nil
		})

		// Start the DHCP server
		dhcpServerDone = dhcpServerStart(originalNS, 1, dhcpServerStopCh)

		// Start the DHCP client daemon
		dhcpPluginPath, err := exec.LookPath("dhcp")
		Expect(err).NotTo(HaveOccurred())
		// Use very short timeouts for lease-unavailable operations because
		// the same test is run many times, and the delays will exceed the
		// `go test` timeout with default delays. Since our DHCP server
		// and client daemon are local processes anyway, we can depend on
		// them to respond very quickly.
		clientCmd = exec.Command(dhcpPluginPath, "daemon", "-socketpath", socketPath, "-timeout", "2s", "-resendmax", "8s", "--resendtimeout", "10s")

		// copy dhcp client's stdout/stderr to test stdout
		var b bytes.Buffer
		mw := io.MultiWriter(os.Stdout, &b)
		clientCmd.Stdout = mw
		clientCmd.Stderr = mw

		err = clientCmd.Start()
		Expect(err).NotTo(HaveOccurred())
		Expect(clientCmd.Process).NotTo(BeNil())

		// Wait up to 15 seconds for the client socket
		Eventually(func() bool {
			_, err := os.Stat(socketPath)
			return err == nil
		}, time.Second*15, time.Second/4).Should(BeTrue())
	})

	AfterEach(func() {
		dhcpServerStopCh <- true
		dhcpServerDone.Wait()
		clientCmd.Process.Kill()
		clientCmd.Wait()

		Expect(originalNS.Close()).To(Succeed())
		Expect(testutils.UnmountNS(originalNS)).To(Succeed())
		Expect(targetNS.Close()).To(Succeed())
		Expect(testutils.UnmountNS(targetNS)).To(Succeed())

		Expect(os.RemoveAll(tmpDir)).To(Succeed())
	})

	for _, ver := range testutils.AllSpecVersions {
		// Redefine ver inside for scope so real value is picked up by each dynamically defined It()
		// See Gingkgo's "Patterns for dynamically generating tests" documentation.
		ver := ver

		It(fmt.Sprintf("[%s] configures multiple links with multiple ADD with second lease unavailable", ver), func() {
			conf := fmt.Sprintf(`{
			    "cniVersion": "%s",
			    "name": "mynet",
			    "type": "bridge",
			    "bridge": "%s",
			    "ipam": {
				"type": "dhcp",
				"daemonSocketPath": "%s"
			    }
			}`, ver, hostBridgeName, socketPath)

			args := &skel.CmdArgs{
				ContainerID: "dummy",
				Netns:       targetNS.Path(),
				IfName:      contVethName0,
				StdinData:   []byte(conf),
			}

			var addResult *types100.Result
			err := originalNS.Do(func(ns.NetNS) error {
				defer GinkgoRecover()

				r, _, err := testutils.CmdAddWithArgs(args, func() error {
					return cmdAdd(args)
				})
				Expect(err).NotTo(HaveOccurred())

				addResult, err = types100.GetResult(r)
				Expect(err).NotTo(HaveOccurred())
				Expect(addResult.IPs).To(HaveLen(1))
				Expect(addResult.IPs[0].Address.String()).To(Equal("192.168.1.5/24"))
				return nil
			})
			Expect(err).NotTo(HaveOccurred())

			args = &skel.CmdArgs{
				ContainerID: "dummy",
				Netns:       targetNS.Path(),
				IfName:      contVethName1,
				StdinData:   []byte(conf),
			}

			err = originalNS.Do(func(ns.NetNS) error {
				defer GinkgoRecover()

				_, _, err := testutils.CmdAddWithArgs(args, func() error {
					return cmdAdd(args)
				})
				Expect(err).To(HaveOccurred())
				println(err.Error())
				Expect(err.Error()).To(Equal("error calling DHCP.Allocate: no more tries"))
				return nil
			})
			Expect(err).NotTo(HaveOccurred())

			args = &skel.CmdArgs{
				ContainerID: "dummy",
				Netns:       targetNS.Path(),
				IfName:      contVethName1,
				StdinData:   []byte(conf),
			}

			err = originalNS.Do(func(ns.NetNS) error {
				return testutils.CmdDelWithArgs(args, func() error {
					return cmdDel(args)
				})
			})
			Expect(err).NotTo(HaveOccurred())

			args = &skel.CmdArgs{
				ContainerID: "dummy",
				Netns:       targetNS.Path(),
				IfName:      contVethName0,
				StdinData:   []byte(conf),
			}

			err = originalNS.Do(func(ns.NetNS) error {
				return testutils.CmdDelWithArgs(args, func() error {
					return cmdDel(args)
				})
			})
			Expect(err).NotTo(HaveOccurred())
		})
	}
})
