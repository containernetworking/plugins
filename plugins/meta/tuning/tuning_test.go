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
	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types/current"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/containernetworking/plugins/pkg/testutils"
	"net"

	"github.com/vishvananda/netlink"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("tuning plugin", func() {
	var originalNS ns.NetNS
	const IFNAME string = "dummy0"

	BeforeEach(func() {
		// Create a new NetNS so we don't modify the host
		var err error
		originalNS, err = testutils.NewNS()
		Expect(err).NotTo(HaveOccurred())

		err = originalNS.Do(func(ns.NetNS) error {
			defer GinkgoRecover()

			err = netlink.LinkAdd(&netlink.Dummy{
				LinkAttrs: netlink.LinkAttrs{
					Name: IFNAME,
				},
			})
			Expect(err).NotTo(HaveOccurred())
			_, err = netlink.LinkByName(IFNAME)
			Expect(err).NotTo(HaveOccurred())
			return nil
		})
		Expect(err).NotTo(HaveOccurred())
	})

	AfterEach(func() {
		Expect(originalNS.Close()).To(Succeed())
	})

	It("passes prevResult through unchanged", func() {
		conf := []byte(`{
	"name": "test",
	"type": "tuning",
	"cniVersion": "0.3.1",
	"sysctl": {
		"net.ipv4.conf.all.log_martians": "1"
	},
	"prevResult": {
		"interfaces": [
			{"name": "dummy0", "sandbox":"netns"}
		],
		"ips": [
			{
				"version": "4",
				"address": "10.0.0.2/24",
				"gateway": "10.0.0.1",
				"interface": 0
			}
		]
	}
}`)

		targetNs, err := testutils.NewNS()
		Expect(err).NotTo(HaveOccurred())
		defer targetNs.Close()

		args := &skel.CmdArgs{
			ContainerID: "dummy",
			Netns:       targetNs.Path(),
			IfName:      IFNAME,
			StdinData:   conf,
		}

		err = originalNS.Do(func(ns.NetNS) error {
			defer GinkgoRecover()

			r, _, err := testutils.CmdAddWithArgs(args, func() error {
				return cmdAdd(args)
			})
			Expect(err).NotTo(HaveOccurred())

			result, err := current.GetResult(r)
			Expect(err).NotTo(HaveOccurred())

			Expect(len(result.Interfaces)).To(Equal(1))
			Expect(result.Interfaces[0].Name).To(Equal(IFNAME))
			Expect(len(result.IPs)).To(Equal(1))
			Expect(result.IPs[0].Address.String()).To(Equal("10.0.0.2/24"))
			return nil
		})
		Expect(err).NotTo(HaveOccurred())
	})

	It("configures and deconfigures promiscuous mode with ADD/DEL", func() {
		conf := []byte(`{
	"name": "test",
	"type": "iplink",
	"cniVersion": "0.3.1",
	"promisc": true,
	"prevResult": {
		"interfaces": [
			{"name": "dummy0", "sandbox":"netns"}
		],
		"ips": [
			{
				"version": "4",
				"address": "10.0.0.2/24",
				"gateway": "10.0.0.1",
				"interface": 0
			}
		]
	}
}`)

		args := &skel.CmdArgs{
			ContainerID: "dummy",
			Netns:       originalNS.Path(),
			IfName:      IFNAME,
			StdinData:   conf,
		}

		err := originalNS.Do(func(ns.NetNS) error {
			defer GinkgoRecover()

			r, _, err := testutils.CmdAddWithArgs(args, func() error {
				return cmdAdd(args)
			})
			Expect(err).NotTo(HaveOccurred())

			result, err := current.GetResult(r)
			Expect(err).NotTo(HaveOccurred())

			Expect(len(result.Interfaces)).To(Equal(1))
			Expect(result.Interfaces[0].Name).To(Equal(IFNAME))
			Expect(len(result.IPs)).To(Equal(1))
			Expect(result.IPs[0].Address.String()).To(Equal("10.0.0.2/24"))

			link, err := netlink.LinkByName(IFNAME)
			Expect(err).NotTo(HaveOccurred())
			Expect(link.Attrs().Promisc).To(Equal(1))

			err = testutils.CmdDel(originalNS.Path(),
				args.ContainerID, "", func() error { return cmdDel(args) })
			Expect(err).NotTo(HaveOccurred())

			return nil
		})
		Expect(err).NotTo(HaveOccurred())
	})

	It("configures and deconfigures mtu with ADD/DEL", func() {
		conf := []byte(`{
	"name": "test",
	"type": "iplink",
	"cniVersion": "0.3.1",
	"mtu": 1454,
	"prevResult": {
		"interfaces": [
			{"name": "dummy0", "sandbox":"netns"}
		],
		"ips": [
			{
				"version": "4",
				"address": "10.0.0.2/24",
				"gateway": "10.0.0.1",
				"interface": 0
			}
		]
	}
}`)

		args := &skel.CmdArgs{
			ContainerID: "dummy",
			Netns:       originalNS.Path(),
			IfName:      IFNAME,
			StdinData:   conf,
		}

		err := originalNS.Do(func(ns.NetNS) error {
			defer GinkgoRecover()

			r, _, err := testutils.CmdAddWithArgs(args, func() error {
				return cmdAdd(args)
			})
			Expect(err).NotTo(HaveOccurred())

			result, err := current.GetResult(r)
			Expect(err).NotTo(HaveOccurred())

			Expect(len(result.Interfaces)).To(Equal(1))
			Expect(result.Interfaces[0].Name).To(Equal(IFNAME))
			Expect(len(result.IPs)).To(Equal(1))
			Expect(result.IPs[0].Address.String()).To(Equal("10.0.0.2/24"))

			link, err := netlink.LinkByName(IFNAME)
			Expect(err).NotTo(HaveOccurred())
			Expect(link.Attrs().MTU).To(Equal(1454))

			err = testutils.CmdDel(originalNS.Path(),
				args.ContainerID, "", func() error { return cmdDel(args) })
			Expect(err).NotTo(HaveOccurred())

			return nil
		})
		Expect(err).NotTo(HaveOccurred())
	})

	It("configures and deconfigures mac address (from conf file) with ADD/DEL", func() {
		conf := []byte(`{
	"name": "test",
	"type": "iplink",
	"cniVersion": "0.3.1",
	"mac": "c2:11:22:33:44:55",
	"prevResult": {
		"interfaces": [
			{"name": "dummy0", "sandbox":"netns"}
		],
		"ips": [
			{
				"version": "4",
				"address": "10.0.0.2/24",
				"gateway": "10.0.0.1",
				"interface": 0
			}
		]
	}
}`)

		args := &skel.CmdArgs{
			ContainerID: "dummy",
			Netns:       originalNS.Path(),
			IfName:      IFNAME,
			StdinData:   conf,
		}

		err := originalNS.Do(func(ns.NetNS) error {
			defer GinkgoRecover()

			r, _, err := testutils.CmdAddWithArgs(args, func() error {
				return cmdAdd(args)
			})
			Expect(err).NotTo(HaveOccurred())

			result, err := current.GetResult(r)
			Expect(err).NotTo(HaveOccurred())

			Expect(len(result.Interfaces)).To(Equal(1))
			Expect(result.Interfaces[0].Name).To(Equal(IFNAME))
			Expect(len(result.IPs)).To(Equal(1))
			Expect(result.IPs[0].Address.String()).To(Equal("10.0.0.2/24"))

			link, err := netlink.LinkByName(IFNAME)
			Expect(err).NotTo(HaveOccurred())
			hw, err := net.ParseMAC("c2:11:22:33:44:55")
			Expect(err).NotTo(HaveOccurred())
			Expect(link.Attrs().HardwareAddr).To(Equal(hw))

			err = testutils.CmdDel(originalNS.Path(),
				args.ContainerID, "", func() error { return cmdDel(args) })
			Expect(err).NotTo(HaveOccurred())

			return nil
		})
		Expect(err).NotTo(HaveOccurred())
	})

	It("configures and deconfigures mac address (from CNI_ARGS) with ADD/DEL", func() {
		conf := []byte(`{
	"name": "test",
	"type": "iplink",
	"cniVersion": "0.3.1",
	"prevResult": {
		"interfaces": [
			{"name": "dummy0", "sandbox":"netns"}
		],
		"ips": [
			{
				"version": "4",
				"address": "10.0.0.2/24",
				"gateway": "10.0.0.1",
				"interface": 0
			}
		]
	}
}`)

		args := &skel.CmdArgs{
			ContainerID: "dummy",
			Netns:       originalNS.Path(),
			IfName:      IFNAME,
			StdinData:   conf,
			Args:        "IgnoreUnknown=true;MAC=c2:11:22:33:44:66",
		}

		err := originalNS.Do(func(ns.NetNS) error {
			defer GinkgoRecover()

			r, _, err := testutils.CmdAddWithArgs(args, func() error {
				return cmdAdd(args)
			})
			Expect(err).NotTo(HaveOccurred())

			result, err := current.GetResult(r)
			Expect(err).NotTo(HaveOccurred())

			Expect(len(result.Interfaces)).To(Equal(1))
			Expect(result.Interfaces[0].Name).To(Equal(IFNAME))
			Expect(len(result.IPs)).To(Equal(1))
			Expect(result.IPs[0].Address.String()).To(Equal("10.0.0.2/24"))

			link, err := netlink.LinkByName(IFNAME)
			Expect(err).NotTo(HaveOccurred())
			hw, err := net.ParseMAC("c2:11:22:33:44:66")
			Expect(err).NotTo(HaveOccurred())
			Expect(link.Attrs().HardwareAddr).To(Equal(hw))

			err = testutils.CmdDel(originalNS.Path(),
				args.ContainerID, "", func() error { return cmdDel(args) })
			Expect(err).NotTo(HaveOccurred())

			return nil
		})
		Expect(err).NotTo(HaveOccurred())
	})
})
