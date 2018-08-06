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
	"io/ioutil"
	"os"
	"strings"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/cni/pkg/types/current"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/containernetworking/plugins/pkg/testutils"

	"github.com/vishvananda/netlink"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

const (
	BRNAME = "bridge0"
	IFNAME = "eth0"
)

// testCase defines the CNI network configuration and the expected
// bridge addresses for a test case.
type testCase struct {
	cniVersion string // CNI Version
}

// Range definition for each entry in the ranges list
type rangeInfo struct {
	subnet  string
	gateway string
}

// netConf() creates a NetConf structure for a test case.
func (tc testCase) netConf() *NetConf {
	return &NetConf{
		NetConf: types.NetConf{
			CNIVersion: tc.cniVersion,
			Name:       "testConfig",
			Type:       "l2-bridge",
		},
		BrName: BRNAME,
		MTU:    5000,
	}
}

// Snippets for generating a JSON network configuration string.
const (
	netConfStr = `
	"cniVersion": "%s",
	"name": "testConfig",
	"type": "bridge",
	"bridge": "%s"`
)

// netConfJSON() generates a JSON network configuration string
// for a test case.
func (tc testCase) netConfJSON(dataDir string) string {
	conf := fmt.Sprintf(netConfStr, tc.cniVersion, BRNAME)
	return "{" + conf + "\n}"
}

var counter uint

// createCmdArgs generates network configuration and creates command
// arguments for a test case.
func (tc testCase) createCmdArgs(targetNS ns.NetNS, dataDir string) *skel.CmdArgs {
	conf := tc.netConfJSON(dataDir)
	defer func() { counter += 1 }()
	return &skel.CmdArgs{
		ContainerID: fmt.Sprintf("dummy-%d", counter),
		Netns:       targetNS.Path(),
		IfName:      IFNAME,
		StdinData:   []byte(conf),
	}
}

type cmdAddDelTester interface {
	setNS(testNS ns.NetNS, targetNS ns.NetNS)
	cmdAddTest(tc testCase, dataDir string)
	cmdDelTest(tc testCase)
}

type testerV03x struct {
	testNS   ns.NetNS
	targetNS ns.NetNS
	args     *skel.CmdArgs
	vethName string
}

func (tester *testerV03x) setNS(testNS ns.NetNS, targetNS ns.NetNS) {
	tester.testNS = testNS
	tester.targetNS = targetNS
}

func (tester *testerV03x) cmdAddTest(tc testCase, dataDir string) {
	// Generate network config and command arguments
	tester.args = tc.createCmdArgs(tester.targetNS, dataDir)

	// Execute cmdADD on the plugin
	var result *current.Result
	err := tester.testNS.Do(func(ns.NetNS) error {
		defer GinkgoRecover()

		r, raw, err := testutils.CmdAddWithArgs(tester.args, func() error {
			return cmdAdd(tester.args)
		})
		Expect(err).NotTo(HaveOccurred())
		Expect(strings.Index(string(raw), "\"interfaces\":")).Should(BeNumerically(">", 0))

		result, err = current.GetResult(r)
		Expect(err).NotTo(HaveOccurred())
		Expect(len(result.Interfaces)).To(Equal(3))
		Expect(result.Interfaces[0].Name).To(Equal(BRNAME))
		Expect(result.Interfaces[0].Mac).To(HaveLen(17))

		Expect(result.Interfaces[1].Name).To(HavePrefix("veth"))
		Expect(result.Interfaces[1].Mac).To(HaveLen(17))

		Expect(result.Interfaces[2].Name).To(Equal(IFNAME))
		Expect(result.Interfaces[2].Mac).To(HaveLen(17)) //mac is random
		Expect(result.Interfaces[2].Sandbox).To(Equal(tester.targetNS.Path()))

		// Make sure bridge link exists
		link, err := netlink.LinkByName(result.Interfaces[0].Name)
		Expect(err).NotTo(HaveOccurred())
		Expect(link.Attrs().Name).To(Equal(BRNAME))
		Expect(link).To(BeAssignableToTypeOf(&netlink.Bridge{}))
		Expect(link.Attrs().HardwareAddr.String()).To(Equal(result.Interfaces[0].Mac))

		// Check for the veth link in the main namespace
		links, err := netlink.LinkList()
		Expect(err).NotTo(HaveOccurred())
		Expect(len(links)).To(Equal(3)) // Bridge, veth, and loopback

		link, err = netlink.LinkByName(result.Interfaces[1].Name)
		Expect(err).NotTo(HaveOccurred())
		Expect(link).To(BeAssignableToTypeOf(&netlink.Veth{}))
		tester.vethName = result.Interfaces[1].Name

		return nil
	})
	Expect(err).NotTo(HaveOccurred())

	// Find the veth peer in the container namespace and the default route
	err = tester.targetNS.Do(func(ns.NetNS) error {
		defer GinkgoRecover()

		link, err := netlink.LinkByName(IFNAME)
		Expect(err).NotTo(HaveOccurred())
		Expect(link.Attrs().Name).To(Equal(IFNAME))
		Expect(link).To(BeAssignableToTypeOf(&netlink.Veth{}))

		return nil
	})
	Expect(err).NotTo(HaveOccurred())
}

func (tester *testerV03x) cmdDelTest(tc testCase) {
	err := tester.testNS.Do(func(ns.NetNS) error {
		defer GinkgoRecover()

		err := testutils.CmdDelWithArgs(tester.args, func() error {
			return cmdDel(tester.args)
		})
		Expect(err).NotTo(HaveOccurred())
		return nil
	})
	Expect(err).NotTo(HaveOccurred())

	// Make sure the host veth has been deleted
	err = tester.targetNS.Do(func(ns.NetNS) error {
		defer GinkgoRecover()

		link, err := netlink.LinkByName(IFNAME)
		Expect(err).To(HaveOccurred())
		Expect(link).To(BeNil())
		return nil
	})
	Expect(err).NotTo(HaveOccurred())

	// Make sure the container veth has been deleted
	err = tester.testNS.Do(func(ns.NetNS) error {
		defer GinkgoRecover()

		link, err := netlink.LinkByName(tester.vethName)
		Expect(err).To(HaveOccurred())
		Expect(link).To(BeNil())
		return nil
	})
}

func cmdAddDelTest(testNS ns.NetNS, tc testCase, dataDir string) {
	// Get a Add/Del tester based on test case version
	tester := &testerV03x{}

	targetNS, err := testutils.NewNS()
	Expect(err).NotTo(HaveOccurred())
	defer targetNS.Close()
	tester.setNS(testNS, targetNS)

	// Test veth allocation
	tester.cmdAddTest(tc, dataDir)

	// Test veth Release
	tester.cmdDelTest(tc)

}

var _ = Describe("bridge Operations", func() {
	var originalNS ns.NetNS
	var dataDir string

	BeforeEach(func() {
		// Create a new NetNS so we don't modify the host
		var err error
		originalNS, err = testutils.NewNS()
		Expect(err).NotTo(HaveOccurred())

		dataDir, err = ioutil.TempDir("", "bridge_test")
		Expect(err).NotTo(HaveOccurred())

		// Do not emulate an error, each test will set this if needed
		debugPostIPAMError = nil
	})

	AfterEach(func() {
		Expect(os.RemoveAll(dataDir)).To(Succeed())
		Expect(originalNS.Close()).To(Succeed())
	})

	It("creates a bridge", func() {
		conf := testCase{cniVersion: "0.3.1"}.netConf()
		err := originalNS.Do(func(ns.NetNS) error {
			defer GinkgoRecover()

			bridge, _, err := setupBridge(conf)
			Expect(err).NotTo(HaveOccurred())
			Expect(bridge.Attrs().Name).To(Equal(BRNAME))

			// Double check that the link was added
			link, err := netlink.LinkByName(BRNAME)
			Expect(err).NotTo(HaveOccurred())
			Expect(link.Attrs().Name).To(Equal(BRNAME))
			Expect(link.Attrs().Promisc).To(Equal(0))
			return nil
		})
		Expect(err).NotTo(HaveOccurred())
	})

	It("handles an existing bridge", func() {
		err := originalNS.Do(func(ns.NetNS) error {
			defer GinkgoRecover()

			err := netlink.LinkAdd(&netlink.Bridge{
				LinkAttrs: netlink.LinkAttrs{
					Name: BRNAME,
				},
			})
			Expect(err).NotTo(HaveOccurred())
			link, err := netlink.LinkByName(BRNAME)
			Expect(err).NotTo(HaveOccurred())
			Expect(link.Attrs().Name).To(Equal(BRNAME))
			ifindex := link.Attrs().Index

			tc := testCase{cniVersion: "0.3.1"}
			conf := tc.netConf()

			bridge, _, err := setupBridge(conf)
			Expect(err).NotTo(HaveOccurred())
			Expect(bridge.Attrs().Name).To(Equal(BRNAME))
			Expect(bridge.Attrs().Index).To(Equal(ifindex))

			// Double check that the link has the same ifindex
			link, err = netlink.LinkByName(BRNAME)
			Expect(err).NotTo(HaveOccurred())
			Expect(link.Attrs().Name).To(Equal(BRNAME))
			Expect(link.Attrs().Index).To(Equal(ifindex))
			return nil
		})
		Expect(err).NotTo(HaveOccurred())
	})

	It("configures and deconfigures a bridge and veth with ADD/DEL for 0.3.0 config", func() {
		tc := testCase{cniVersion: "0.3.0"}
		cmdAddDelTest(originalNS, tc, dataDir)
	})

	It("configures and deconfigures a bridge and veth with ADD/DEL for 0.3.1 config", func() {
		tc := testCase{cniVersion: "0.3.1"}
		cmdAddDelTest(originalNS, tc, dataDir)
	})

	It("deconfigures an unconfigured bridge with DEL", func() {
		tc := testCase{cniVersion: "0.3.0"}

		tester := testerV03x{}
		targetNS, err := testutils.NewNS()
		Expect(err).NotTo(HaveOccurred())
		defer targetNS.Close()
		tester.setNS(originalNS, targetNS)
		tester.args = tc.createCmdArgs(targetNS, dataDir)

		// Execute cmdDEL on the plugin, expect no errors
		tester.cmdDelTest(tc)
	})

	It("ensure promiscuous mode on bridge", func() {
		const IFNAME = "bridge0"

		conf := &NetConf{
			NetConf: types.NetConf{
				CNIVersion: "0.3.1",
				Name:       "testConfig",
				Type:       "bridge",
			},
			BrName:      IFNAME,
			HairpinMode: false,
			PromiscMode: true,
			MTU:         5000,
		}

		err := originalNS.Do(func(ns.NetNS) error {
			defer GinkgoRecover()

			_, _, err := setupBridge(conf)
			Expect(err).NotTo(HaveOccurred())

			//Check if promiscuous mode is set correctly
			link, err := netlink.LinkByName("bridge0")
			Expect(err).NotTo(HaveOccurred())

			Expect(link.Attrs().Promisc).To(Equal(1))

			return nil
		})
		Expect(err).NotTo(HaveOccurred())
	})
})
