// Copyright 2016 CNI authors
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

package ip_test

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"net"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/vishvananda/netlink"

	"github.com/containernetworking/plugins/pkg/ip"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/containernetworking/plugins/pkg/testutils"
)

var _ = Describe("Link", func() {
	const (
		ifaceFormatString string = "i%d"
		mtu               int    = 1400
		ip4onehwaddr             = "0a:58:01:01:01:01"
	)
	var (
		hostNetNS         ns.NetNS
		containerNetNS    ns.NetNS
		ifaceCounter      int = 0
		hostVeth          net.Interface
		containerVeth     net.Interface
		hostVethName      string
		containerVethName string

		originalRandReader = rand.Reader
	)

	BeforeEach(func() {
		var err error

		hostNetNS, err = testutils.NewNS()
		Expect(err).NotTo(HaveOccurred())

		containerNetNS, err = testutils.NewNS()
		Expect(err).NotTo(HaveOccurred())

		fakeBytes := make([]byte, 20)
		// to be reset in AfterEach block
		rand.Reader = bytes.NewReader(fakeBytes)

		_ = containerNetNS.Do(func(ns.NetNS) error {
			defer GinkgoRecover()

			hostVeth, containerVeth, err = ip.SetupVeth(fmt.Sprintf(ifaceFormatString, ifaceCounter), mtu, "", hostNetNS)
			if err != nil {
				return err
			}
			Expect(err).NotTo(HaveOccurred())

			hostVethName = hostVeth.Name
			containerVethName = containerVeth.Name

			return nil
		})
	})

	AfterEach(func() {
		Expect(containerNetNS.Close()).To(Succeed())
		Expect(hostNetNS.Close()).To(Succeed())
		ifaceCounter++
		rand.Reader = originalRandReader
	})

	Describe("GetVethPeerIfindex", func() {
		It("returns the link and peer index of the named interface", func() {
			By("looking up the container veth index using the host veth name")
			_ = hostNetNS.Do(func(ns.NetNS) error {
				defer GinkgoRecover()

				gotHostLink, gotContainerIndex, err := ip.GetVethPeerIfindex(hostVethName)
				Expect(err).NotTo(HaveOccurred())

				By("checking we got back the host link")
				attrs := gotHostLink.Attrs()
				Expect(attrs.Index).To(Equal(hostVeth.Index))
				Expect(attrs.Name).To(Equal(hostVeth.Name))

				By("checking we got back the container veth index")
				Expect(gotContainerIndex).To(Equal(containerVeth.Index))

				return nil
			})

			By("looking up the host veth index using the container veth name")
			_ = containerNetNS.Do(func(ns.NetNS) error {
				defer GinkgoRecover()

				gotContainerLink, gotHostIndex, err := ip.GetVethPeerIfindex(containerVethName)
				Expect(err).NotTo(HaveOccurred())

				By("checking we got back the container link")
				attrs := gotContainerLink.Attrs()
				Expect(attrs.Index).To(Equal(containerVeth.Index))
				Expect(attrs.Name).To(Equal(containerVeth.Name))

				By("checking we got back the host veth index")
				Expect(gotHostIndex).To(Equal(hostVeth.Index))

				return nil
			})
		})
	})

	It("SetupVeth must put the veth endpoints into the separate namespaces", func() {
		_ = containerNetNS.Do(func(ns.NetNS) error {
			defer GinkgoRecover()

			containerVethFromName, err := netlink.LinkByName(containerVethName)
			Expect(err).NotTo(HaveOccurred())
			Expect(containerVethFromName.Attrs().Index).To(Equal(containerVeth.Index))

			return nil
		})

		_ = hostNetNS.Do(func(ns.NetNS) error {
			defer GinkgoRecover()

			hostVethFromName, err := netlink.LinkByName(hostVethName)
			Expect(err).NotTo(HaveOccurred())
			Expect(hostVethFromName.Attrs().Index).To(Equal(hostVeth.Index))

			return nil
		})
	})

	Context("when container already has an interface with the same name", func() {
		It("returns useful error", func() {
			_ = containerNetNS.Do(func(ns.NetNS) error {
				defer GinkgoRecover()
				testHostVethName := "test" + hostVethName
				_, _, err := ip.SetupVethWithName(containerVethName, testHostVethName, mtu, "", hostNetNS)
				Expect(err.Error()).To(Equal(fmt.Sprintf("container veth name (%q) peer provided (%q) already exists", containerVethName, testHostVethName)))

				return nil
			})
		})
	})

	Context("deleting an non-existent device", func() {
		It("returns known error", func() {
			_ = containerNetNS.Do(func(ns.NetNS) error {
				defer GinkgoRecover()

				// This string should match the expected error codes in the cmdDel functions of some of the plugins
				_, err := ip.DelLinkByNameAddr("THIS_DONT_EXIST")
				Expect(err).To(Equal(ip.ErrLinkNotFound))

				return nil
			})
		})
	})

	Context("when there is no name available for the host-side", func() {
		BeforeEach(func() {
			// adding different interface to container ns
			containerVethName += "0"
		})
		It("returns useful error", func() {
			_ = containerNetNS.Do(func(ns.NetNS) error {
				defer GinkgoRecover()
				_, _, err := ip.SetupVethWithName(containerVethName, hostVethName, mtu, "", hostNetNS)
				Expect(err.Error()).To(Equal(fmt.Sprintf("container veth name (%q) peer provided (%q) already exists", containerVethName, hostVethName)))
				return nil
			})
		})
	})

	Context("when there is no name conflict for the host or container interfaces", func() {
		BeforeEach(func() {
			// adding different interface to container and host ns
			containerVethName += "0"
			rand.Reader = originalRandReader
		})
		It("successfully creates the second veth pair", func() {
			_ = containerNetNS.Do(func(ns.NetNS) error {
				defer GinkgoRecover()

				hostVeth, _, err := ip.SetupVeth(containerVethName, mtu, "", hostNetNS)
				Expect(err).NotTo(HaveOccurred())
				hostVethName = hostVeth.Name
				return nil
			})

			// verify veths are in different namespaces
			_ = containerNetNS.Do(func(ns.NetNS) error {
				defer GinkgoRecover()

				_, err := netlink.LinkByName(containerVethName)
				Expect(err).NotTo(HaveOccurred())

				return nil
			})

			_ = hostNetNS.Do(func(ns.NetNS) error {
				defer GinkgoRecover()

				_, err := netlink.LinkByName(hostVethName)
				Expect(err).NotTo(HaveOccurred())

				return nil
			})
		})

		It("successfully creates a veth pair with an explicit mac", func() {
			const mac = "02:00:00:00:01:23"
			_ = containerNetNS.Do(func(ns.NetNS) error {
				defer GinkgoRecover()

				hostVeth, _, err := ip.SetupVeth(containerVethName, mtu, mac, hostNetNS)
				Expect(err).NotTo(HaveOccurred())
				hostVethName = hostVeth.Name

				link, err := netlink.LinkByName(containerVethName)
				Expect(err).NotTo(HaveOccurred())
				Expect(link.Attrs().HardwareAddr.String()).To(Equal(mac))

				return nil
			})

			_ = hostNetNS.Do(func(ns.NetNS) error {
				defer GinkgoRecover()

				link, err := netlink.LinkByName(hostVethName)
				Expect(err).NotTo(HaveOccurred())
				Expect(link.Attrs().HardwareAddr.String()).NotTo(Equal(mac))

				return nil
			})
		})
	})

	It("DelLinkByName must delete the veth endpoints", func() {
		_ = containerNetNS.Do(func(ns.NetNS) error {
			defer GinkgoRecover()

			// this will delete the host endpoint too
			err := ip.DelLinkByName(containerVethName)
			Expect(err).NotTo(HaveOccurred())

			_, err = netlink.LinkByName(containerVethName)
			Expect(err).To(HaveOccurred())

			return nil
		})

		_ = hostNetNS.Do(func(ns.NetNS) error {
			defer GinkgoRecover()

			_, err := netlink.LinkByName(hostVethName)
			Expect(err).To(HaveOccurred())

			return nil
		})
	})

	It("DelLinkByNameAddr should return no IPs when no IPs are configured", func() {
		_ = containerNetNS.Do(func(ns.NetNS) error {
			defer GinkgoRecover()

			// this will delete the host endpoint too
			addr, err := ip.DelLinkByNameAddr(containerVethName)
			Expect(err).NotTo(HaveOccurred())
			Expect(addr).To(BeEmpty())
			return nil
		})
	})
})
