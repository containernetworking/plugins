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
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"syscall"
	"time"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types/current"
	"github.com/containernetworking/plugins/pkg/ip"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/containernetworking/plugins/pkg/testutils"

	"github.com/vishvananda/netlink"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func checksum(b []byte) uint16 {
	csumcv := len(b) - 1 // checksum coverage
	s := uint32(0)
	for i := 0; i < csumcv; i += 2 {
		s += uint32(b[i+1])<<8 | uint32(b[i])
	}
	if csumcv&1 == 0 {
		s += uint32(b[csumcv])
	}
	s = s>>16 + s&0xffff
	s = s + s>>16
	return ^uint16(s)
}

func slaacRouterRun(origNS ns.NetNS, link net.Interface, stopCh <-chan bool) error {
	// Get the "router" link in the original netns
	var srcIP *net.IP
	var srcMAC *net.HardwareAddr
	if err := origNS.Do(func(ns.NetNS) error {
		srcMAC = &link.HardwareAddr

		nlink, err := netlink.LinkByName(link.Name)
		if err != nil {
			return fmt.Errorf("failed to re-fetch link %q: %v", link.Name, err)
		}

		// Get IPv6LL address, making sure we wait until it has completed DAD,
		// otherwise we cannot send from it
	loop:
		for i := 0; i < 10; i++ {
			addrs, err := netlink.AddrList(nlink, syscall.AF_INET6)
			if err != nil {
				return fmt.Errorf("failed to read IPv6 addresses from RA link: %v", err)
			}
			for _, a := range addrs {
				if a.IP.IsLinkLocalUnicast() && (a.Flags&syscall.IFA_F_TENTATIVE) == 0 {
					srcIP = &a.IP
					break loop
				}
			}
			time.Sleep(time.Second / 2)
		}
		if srcIP == nil {
			return fmt.Errorf("failed to retrieve non-tentative IPv6LL address")
		}

		return nil
	}); err != nil {
		return err
	}

	if srcIP == nil {
		return fmt.Errorf("failed to find IPv6 address from RA link")
	}
	if srcMAC == nil {
		return fmt.Errorf("failed to find IPv6 address from RA link")
	}

	// Header + source LL address option + prefix information option
	bytes := make([]byte, 16+8+32)

	// ICMPv6 header
	bytes[0] = 134                           // icmp6_type
	bytes[1] = 0                             // icmp6_code
	binary.BigEndian.PutUint16(bytes[2:], 0) // icmp6_cksum (zero when calculating)

	// RA fields
	bytes[4] = 0                                 // curhoplmit
	bytes[5] = 0                                 // flags_reserved
	binary.BigEndian.PutUint16(bytes[6:], 1800)  // nd_ra_router_lifetime
	binary.BigEndian.PutUint32(bytes[8:], 5000)  // nd_ra_reachable
	binary.BigEndian.PutUint32(bytes[12:], 1000) // nd_ra_retransmit

	// Options
	bytes[16] = 1 // Option Type - "source link layer address"
	bytes[17] = 1 // Option Len  - units of 8 octets
	copy(bytes[18:], *srcMAC)

	bytes[24] = 3                                 // Option Type - "prefix information"
	bytes[25] = 4                                 // Option Len  - units of 8 octets
	bytes[26] = 64                                // Prefix length
	bytes[27] = 0xC0                              // Flags - L and A bits set
	binary.BigEndian.PutUint32(bytes[28:], 86400) // prefix valid lifetime
	binary.BigEndian.PutUint32(bytes[32:], 14400) // prefix preferred lifetime
	prefix, _, err := net.ParseCIDR("2001:db8:1::/64")
	if err != nil {
		return fmt.Errorf("failed to parse prefix: %v", err)
	}
	copy(bytes[40:], prefix.To16())

	// pseudo-header for checksum calculations
	// Length = source IP (16 bytes) + destination IP (16 bytes)
	//   + upper layer packet length (4 bytes) + zero (3 bytes)
	//   + next header (1 byte) + ICMPv6 header (16 bytes)
	//   + ICMPv6 RA options (40 bytes)
	ph := make([]byte, 16+16+4+3+1+16+40)
	copy(ph, *srcIP)
	dstIP := net.ParseIP("ff02::1")
	copy(ph[16:], dstIP)
	ph[34] = (16 + 8) / 255 // Upper layer packet length
	ph[35] = (16 + 8) % 255 // Upper layer packet length
	ph[39] = syscall.IPPROTO_ICMPV6
	copy(ph[40:], bytes)

	// Checksum the pseudoheader and dump into actual header
	csum := checksum(ph)
	bytes[2] = byte(csum)
	bytes[3] = byte(csum >> 8)

	sa := &syscall.SockaddrInet6{}
	copy(sa.Addr[0:], dstIP)

	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		if err := origNS.Do(func(ns.NetNS) error {
			// Open the socket
			data := make([]byte, 2)
			binary.BigEndian.PutUint16(data, syscall.IPPROTO_ICMPV6)
			pbe := binary.BigEndian.Uint16(data)
			sock, err := syscall.Socket(syscall.AF_INET6, syscall.SOCK_RAW, int(pbe))
			if err != nil {
				return fmt.Errorf("failed to open raw sock: %v", err)
			}
			defer syscall.Close(sock)
			if err := syscall.SetsockoptString(sock, syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, link.Name); err != nil {
				return fmt.Errorf("failed to bind to device: %v", err)
			}
			if err := syscall.SetsockoptInt(sock, syscall.IPPROTO_IPV6, syscall.IPV6_MULTICAST_HOPS, 255); err != nil {
				return fmt.Errorf("failed to set MC hops: %v", err)
			}

			wg.Done()
			for {
				// Send an RA every 3 seconds until told to stop
				if err := syscall.Sendto(sock, bytes, 0, sa); err != nil {
					return fmt.Errorf("failed to send RA: %v", err)
				}
				select {
				case <-time.After(time.Second * 3):
					break
				case <-stopCh:
					return nil
				}
			}
		}); err != nil {
			fmt.Printf("Error sending router advertisements: %v\n", err)
		}
	}()
	wg.Wait()

	return nil
}

const LINK_NAME = "eth0"

var _ = Describe("slaac Operations", func() {
	var originalNS, targetNS ns.NetNS
	var hostVeth, contVeth net.Interface

	BeforeEach(func() {
		// Create a new NetNS so we don't modify the host
		var err error
		originalNS, err = ns.NewNS()
		Expect(err).NotTo(HaveOccurred())

		// Create the target/container namespace
		targetNS, err = ns.NewNS()
		Expect(err).NotTo(HaveOccurred())

		err = targetNS.Do(func(hostNS ns.NetNS) error {
			defer GinkgoRecover()
			hostVeth, contVeth, err = ip.SetupVeth(LINK_NAME, 1500, originalNS)
			Expect(err).NotTo(HaveOccurred())
			return nil
		})
		Expect(err).NotTo(HaveOccurred())
	})

	AfterEach(func() {
		Expect(originalNS.Close()).To(Succeed())
		Expect(targetNS.Close()).To(Succeed())
	})

	It("successfully configures IPv6 with SLAAC with ADD/DEL", func() {
		conf := `{
    "cniVersion": "0.3.1",
    "name": "mynet",
    "type": "foobar",
    "ipam": {
        "type": "slaac"
    }
}`
		args := &skel.CmdArgs{
			ContainerID: "dummy",
			Netns:       targetNS.Path(),
			IfName:      LINK_NAME,
			StdinData:   []byte(conf),
		}

		stopCh := make(chan bool)
		defer func() {
			stopCh <- true
		}()

		err := slaacRouterRun(originalNS, hostVeth, stopCh)
		Expect(err).NotTo(HaveOccurred())

		err = originalNS.Do(func(ns.NetNS) error {
			defer GinkgoRecover()

			r, _, err := testutils.CmdAddWithResult(targetNS.Path(), LINK_NAME, []byte(conf), func() error {
				return cmdAdd(args)
			})
			Expect(err).NotTo(HaveOccurred())

			result, err := current.GetResult(r)
			Expect(err).NotTo(HaveOccurred())

			Expect(len(result.Interfaces)).To(Equal(0))
			Expect(len(result.IPs)).To(Equal(1))

			expectedIPStr := fmt.Sprintf("2001:db8:1::%02x%02x:%02xff:fe%02x:%02x%02x/64",
				contVeth.HardwareAddr[0]^2,
				contVeth.HardwareAddr[1],
				contVeth.HardwareAddr[2],
				contVeth.HardwareAddr[3],
				contVeth.HardwareAddr[4],
				contVeth.HardwareAddr[5])
			expectedIP, expectedIPNet, err := net.ParseCIDR(expectedIPStr)
			Expect(err).NotTo(HaveOccurred())
			expectedIPNet.IP = expectedIP

			expectedGwStr := fmt.Sprintf("fe80::%02x%02x:%02xff:fe%02x:%02x%02x",
				hostVeth.HardwareAddr[0]^2,
				hostVeth.HardwareAddr[1],
				hostVeth.HardwareAddr[2],
				hostVeth.HardwareAddr[3],
				hostVeth.HardwareAddr[4],
				hostVeth.HardwareAddr[5])
			expectedGw := net.ParseIP(expectedGwStr)
			Expect(expectedGw).NotTo(Equal(nil))

			Expect(result.IPs[0].Address).To(Equal(*expectedIPNet))
			Expect(result.IPs[0].Gateway.Equal(expectedGw)).To(Equal(true))
			return nil
		})
		Expect(err).NotTo(HaveOccurred())

		err = originalNS.Do(func(ns.NetNS) error {
			defer GinkgoRecover()

			err = testutils.CmdDelWithResult(targetNS.Path(), LINK_NAME, func() error {
				return cmdDel(args)
			})
			Expect(err).NotTo(HaveOccurred())
			return nil
		})
		Expect(err).NotTo(HaveOccurred())
	})
})
