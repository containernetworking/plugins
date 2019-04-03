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

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/cni/pkg/types/current"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/containernetworking/plugins/pkg/testutils"

	"github.com/vishvananda/netlink"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("ptp Operations", func() {
	var originalNS ns.NetNS

	BeforeEach(func() {
		// Create a new NetNS so we don't modify the host.
		var err error
		originalNS, err = testutils.NewNS()
		Expect(err).NotTo(HaveOccurred())
	})

	AfterEach(func() {
		Expect(originalNS.Close()).To(Succeed())
	})

	createPTP := func(ifName, containerID, conf string, numIPs int) (ns.NetNS, []*current.IPConfig) {
		targetNS, err := testutils.NewNS()
		Expect(err).NotTo(HaveOccurred())

		args := &skel.CmdArgs{
			ContainerID: containerID,
			Netns:       targetNS.Path(),
			IfName:      ifName,
			StdinData:   []byte(conf),
		}

		var ips []*current.IPConfig
		var resI types.Result
		var res *current.Result

		// Execute the plugin with the ADD command, creating the veth endpoints.
		err = originalNS.Do(func(ns.NetNS) error {
			defer GinkgoRecover()

			resI, _, err = testutils.CmdAddWithArgs(args, func() error {
				return cmdAdd(args)
			})
			Expect(err).NotTo(HaveOccurred())
			return nil
		})
		Expect(err).NotTo(HaveOccurred())

		res, err = current.NewResultFromResult(resI)
		Expect(err).NotTo(HaveOccurred())

		// Make sure ptp link exists in the target namespace.
		wantMac := ""
		err = targetNS.Do(func(ns.NetNS) error {
			defer GinkgoRecover()

			link, err := netlink.LinkByName(ifName)
			Expect(err).NotTo(HaveOccurred())
			wantMac = link.Attrs().HardwareAddr.String()

			for _, ipc := range res.IPs {
				if *ipc.Interface != 1 {
					continue
				}
				ips = append(ips, ipc)
			}

			return nil
		})
		Expect(err).NotTo(HaveOccurred())

		// Make sure the interfaces are correct.
		Expect(res.Interfaces).To(HaveLen(2))

		Expect(res.Interfaces[0].Name).To(HavePrefix("veth"))
		Expect(res.Interfaces[0].Mac).To(HaveLen(17))
		Expect(res.Interfaces[0].Sandbox).To(BeEmpty())

		Expect(res.Interfaces[1].Name).To(Equal(ifName))
		Expect(res.Interfaces[1].Mac).To(Equal(wantMac))
		Expect(res.Interfaces[1].Sandbox).To(Equal(targetNS.Path()))

		Expect(len(ips)).To(Equal(numIPs))

		return targetNS, ips
	}

	deletePTP := func(ifName, containerID, conf string, targetNS ns.NetNS) {
		args := &skel.CmdArgs{
			ContainerID: containerID,
			Netns:       targetNS.Path(),
			IfName:      ifName,
			StdinData:   []byte(conf),
		}

		// Call the plugins with the DEL command, deleting the veth endpoints.
		err := originalNS.Do(func(ns.NetNS) error {
			defer GinkgoRecover()

			err := testutils.CmdDelWithArgs(args, func() error {
				return cmdDel(args)
			})
			Expect(err).NotTo(HaveOccurred())
			return nil
		})
		Expect(err).NotTo(HaveOccurred())

		// Make sure ptp link has been deleted.
		err = targetNS.Do(func(ns.NetNS) error {
			defer GinkgoRecover()

			link, err := netlink.LinkByName(ifName)
			Expect(err).To(HaveOccurred())
			Expect(link).To(BeNil())
			return nil
		})
		Expect(err).NotTo(HaveOccurred())
	}

	doTest := func(conf string, numIPs int) {
		const IFNAME = "ptp0"

		// Execute the plugin with the ADD command, creating the veth endpoints.
		srcNS, sips := createPTP(IFNAME, "dummy_src", conf, numIPs)
		defer srcNS.Close()

		dstNS, dips := createPTP(IFNAME, "dummy_dst", conf, numIPs)
		defer dstNS.Close()

		// Add a fake IPv4 route to gw with respect to loopback dev.
		err := originalNS.Do(func(ns.NetNS) error {
			defer GinkgoRecover()

			lo, err := netlink.LinkByName("lo")
			if err != nil {
				return fmt.Errorf("failed to find loopback dev: %v", err)
			}

			if err := netlink.LinkSetUp(lo); err != nil {
				return fmt.Errorf("failed to set loopback dev up: %v", err)
			}

			for _, ipc := range sips {
				if ipc.Version == "6" {
					continue
				}
				if err = netlink.RouteAdd(&netlink.Route{
					LinkIndex: lo.Attrs().Index,
					Scope:     netlink.SCOPE_LINK,
					Dst: &net.IPNet{
						IP:   ipc.Gateway,
						Mask: net.CIDRMask(32, 32),
					},
				}); err != nil {
					return fmt.Errorf("failed to add gw route to loopback dev: %v", err)
				}
			}
			return nil
		})
		Expect(err).NotTo(HaveOccurred())

		err = srcNS.Do(func(ns.NetNS) error {
			defer GinkgoRecover()

			for i := 0; i < numIPs; i++ {
				saddr := sips[i].Address.IP.String()
				daddr := dips[i].Address.IP.String()
				fmt.Fprintln(GinkgoWriter, "ping", saddr, "->", daddr)

				if err := testutils.Ping(saddr, daddr, (sips[i].Version == "6"), 30); err != nil {
					return fmt.Errorf("ping %s -> %s failed: %s", saddr, daddr, err)
				}
			}
			return nil
		})
		Expect(err).NotTo(HaveOccurred())

		deletePTP(IFNAME, "dummy_src", conf, srcNS)
		deletePTP(IFNAME, "dummy_dst", conf, dstNS)
	}

	It("configures and deconfigures a ptp link with ADD/DEL", func() {
		conf := `{
    "cniVersion": "0.3.1",
    "name": "mynet",
    "type": "ptp",
    "ipMasq": true,
    "mtu": 5000,
    "ipam": {
        "type": "host-local",
        "subnet": "10.1.2.0/24"
    }
}`

		doTest(conf, 1)
	})

	It("configures and deconfigures a dual-stack ptp link with ADD/DEL", func() {
		conf := `{
    "cniVersion": "0.3.1",
    "name": "mynet",
    "type": "ptp",
    "ipMasq": true,
    "mtu": 5000,
    "ipam": {
        "type": "host-local",
		"ranges": [
			[{ "subnet": "10.1.2.0/24"}],
			[{ "subnet": "2001:db8:1::0/66"}]
		]
    }
}`

		doTest(conf, 2)
	})

	It("deconfigures an unconfigured ptp link with DEL", func() {
		const IFNAME = "ptp0"

		conf := `{
    "cniVersion": "0.3.0",
    "name": "mynet",
    "type": "ptp",
    "ipMasq": true,
    "mtu": 5000,
    "ipam": {
        "type": "host-local",
        "subnet": "10.1.2.0/24"
    }
}`

		targetNs, err := testutils.NewNS()
		Expect(err).NotTo(HaveOccurred())
		defer targetNs.Close()

		args := &skel.CmdArgs{
			ContainerID: "dummy",
			Netns:       targetNs.Path(),
			IfName:      IFNAME,
			StdinData:   []byte(conf),
		}

		// Call the plugins with the DEL command. It should not error even though the veth doesn't exist.
		err = originalNS.Do(func(ns.NetNS) error {
			defer GinkgoRecover()

			err := testutils.CmdDelWithArgs(args, func() error {
				return cmdDel(args)
			})
			Expect(err).NotTo(HaveOccurred())
			return nil
		})
		Expect(err).NotTo(HaveOccurred())
	})
})
