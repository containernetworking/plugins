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
	"net"
	"os"
	"os/exec"
	"reflect"
	"sync"
	"time"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types/current"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/containernetworking/plugins/pkg/testutils"

	"github.com/vishvananda/netlink"

	"github.com/d2g/dhcp4"
	"github.com/d2g/dhcp4server"
	"github.com/d2g/dhcp4server/leasepool"
	"github.com/d2g/dhcp4server/leasepool/memorypool"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func dhcpServerStart(netns ns.NetNS, leaseIP, serverIP net.IP, stopCh <-chan bool) error {
	// Add the expected IP to the pool
	lp := memorypool.MemoryPool{}
	err := lp.AddLease(leasepool.Lease{IP: dhcp4.IPAdd(net.IPv4(192, 168, 1, 5), 0)})
	if err != nil {
		return fmt.Errorf("error adding IP to DHCP pool: %v", err)
	}

	dhcpServer, err := dhcp4server.New(
		net.IPv4(192, 168, 1, 1),
		&lp,
		dhcp4server.SetLocalAddr(net.UDPAddr{IP: net.IPv4(0, 0, 0, 0), Port: 67}),
		dhcp4server.SetRemoteAddr(net.UDPAddr{IP: net.IPv4bcast, Port: 68}),
		dhcp4server.LeaseDuration(time.Minute*15),
	)
	if err != nil {
		return fmt.Errorf("failed to create DHCP server: %v", err)
	}

	wg := sync.WaitGroup{}
	wg.Add(2)
	go func() {
		defer GinkgoRecover()

		err = netns.Do(func(ns.NetNS) error {
			wg.Done()
			return dhcpServer.ListenAndServe()
		})
		Expect(err).NotTo(HaveOccurred())
	}()

	go func() {
		wg.Done()
		// Stop DHCP server in another goroutine so we don't block main one
		<-stopCh
		dhcpServer.Shutdown()
	}()
	wg.Wait()

	return nil
}

var _ = Describe("DHCP Operations", func() {
	var originalNS, targetNS ns.NetNS
	var stopCh chan bool
	var clientCmd *exec.Cmd
	const (
		hostVethName string = "dhcp0"
		contVethName string = "eth0"
		pidfilePath  string = "/var/run/cni/dhcp-client.pid"
	)

	BeforeEach(func() {
		stopCh = make(chan bool)

		// Create a new NetNS so we don't modify the host
		var err error
		originalNS, err = ns.NewNS()
		Expect(err).NotTo(HaveOccurred())

		targetNS, err = ns.NewNS()
		Expect(err).NotTo(HaveOccurred())

		serverIP := net.IPNet{
			IP:   net.IPv4(192, 168, 1, 1),
			Mask: net.IPv4Mask(255, 255, 255, 0),
		}

		// Create a veth pair in the "host" (original) NS
		err = originalNS.Do(func(ns.NetNS) error {
			defer GinkgoRecover()

			err = netlink.LinkAdd(&netlink.Veth{
				LinkAttrs: netlink.LinkAttrs{
					Name: hostVethName,
				},
				PeerName: contVethName,
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
		err = dhcpServerStart(originalNS, net.IPv4(192, 168, 1, 5), serverIP.IP, stopCh)
		Expect(err).NotTo(HaveOccurred())

		// Start the DHCP client daemon
		os.MkdirAll(pidfilePath, 0755)
		dhcpPluginPath, err := exec.LookPath("dhcp")
		Expect(err).NotTo(HaveOccurred())
		clientCmd = exec.Command(dhcpPluginPath, "daemon")
		err = clientCmd.Start()
		Expect(err).NotTo(HaveOccurred())
		Expect(clientCmd.Process).NotTo(BeNil())

		// Wait for the client socket
		ok := false
		for i := 0; i < 10; i++ {
			if _, err := os.Stat(socketPath); err == nil {
				ok = true
				break
			}
			time.Sleep(time.Second / 2)
		}
		Expect(ok).To(BeTrue())
	})

	AfterEach(func() {
		stopCh <- true
		clientCmd.Process.Kill()
		clientCmd.Process.Release()
		Expect(originalNS.Close()).To(Succeed())
		Expect(targetNS.Close()).To(Succeed())
		os.Remove(socketPath)
		os.Remove(pidfilePath)
	})

	It("configures and deconfigures an link with ADDDEL", func() {
		conf := `{
    "cniVersion": "0.3.1",
    "name": "mynet",
    "type": "ipvlan",
    "ipam": {
        "type": "dhcp"
    }
}`

		args := &skel.CmdArgs{
			ContainerID: "dummy",
			Netns:       targetNS.Path(),
			IfName:      contVethName,
			StdinData:   []byte(conf),
		}

		var addResult *current.Result
		err := originalNS.Do(func(ns.NetNS) error {
			defer GinkgoRecover()

			r, _, err := testutils.CmdAddWithResult(targetNS.Path(), contVethName, []byte(conf), func() error {
				return cmdAdd(args)
			})
			Expect(err).NotTo(HaveOccurred())

			addResult, err = current.GetResult(r)
			Expect(err).NotTo(HaveOccurred())
			Expect(len(addResult.IPs)).To(Equal(1))
			Expect(addResult.IPs[0].Address.String()).To(Equal("192.168.1.5/24"))
			return nil
		})
		Expect(err).NotTo(HaveOccurred())

		err = originalNS.Do(func(ns.NetNS) error {
			return testutils.CmdDelWithResult(targetNS.Path(), contVethName, func() error {
				return cmdDel(args)
			})
		})
		Expect(err).NotTo(HaveOccurred())
	})
})
