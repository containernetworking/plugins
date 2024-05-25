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
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/coreos/go-iptables/iptables"
	"github.com/networkplumbing/go-nft/nft"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"sigs.k8s.io/knftables"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	types040 "github.com/containernetworking/cni/pkg/types/040"
	types100 "github.com/containernetworking/cni/pkg/types/100"
	"github.com/containernetworking/plugins/pkg/ip"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/containernetworking/plugins/pkg/testutils"
	"github.com/containernetworking/plugins/plugins/ipam/host-local/backend/allocator"
)

const (
	BRNAME     = "bridge0"
	BRNAMEVLAN = "bridge0.100"
	IFNAME     = "eth0"
	NAMESERVER = "192.0.2.0"
)

type Net struct {
	Name       string                `json:"name"`
	CNIVersion string                `json:"cniVersion"`
	Type       string                `json:"type,omitempty"`
	BrName     string                `json:"bridge"`
	IPAM       *allocator.IPAMConfig `json:"ipam"`
	// RuntimeConfig struct {    // The capability arg
	//	IPRanges []RangeSet `json:"ipRanges,omitempty"`
	// Args *struct {
	// } `json:"runtimeConfig,omitempty"`

	//	A *IPAMArgs `json:"cni"`
	DNS           types.DNS              `json:"dns"`
	RawPrevResult map[string]interface{} `json:"prevResult,omitempty"`
	PrevResult    types100.Result        `json:"-"`
}

// testCase defines the CNI network configuration and the expected
// bridge addresses for a test case.
type testCase struct {
	cniVersion        string      // CNI Version
	subnet            string      // Single subnet config: Subnet CIDR
	gateway           string      // Single subnet config: Gateway
	ranges            []rangeInfo // Ranges list (multiple subnets config)
	resolvConf        string      // host-local resolvConf file path
	isGW              bool
	isLayer2          bool
	expGWCIDRs        []string // Expected gateway addresses in CIDR form
	vlan              int
	vlanTrunk         []*VlanTrunk
	removeDefaultVlan bool
	ipMasq            bool
	ipMasqBackend     string
	macspoofchk       bool
	disableContIface  bool

	AddErr020 string
	DelErr020 string
	AddErr010 string
	DelErr010 string

	envArgs       string // CNI_ARGS
	runtimeConfig struct {
		mac string
	}
	args struct {
		cni struct {
			mac string
		}
	}

	// Unlike the parameters above, the following parameters
	// are expected values to be checked against.
	// e.g. the mac address has several sources: CNI_ARGS, Args and RuntimeConfig.
	expectedMac string
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
			Type:       "bridge",
		},
		BrName: BRNAME,
		IsGW:   tc.isGW,
		IPMasq: false,
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

	vlan = `,
	"vlan": %d`

	vlanTrunkStartStr = `,
	"vlanTrunk": [`

	vlanTrunk = `
	{
		"id": %d
	}`

	vlanTrunkRange = `
	{
		"minID": %d,
		"maxID": %d
	}`

	vlanTrunkEndStr = `
	]`

	preserveDefaultVlan = `,
	"preserveDefaultVlan": false`

	netDefault = `,
	"isDefaultGateway": true`

	disableContainerInterface = `,
    "disableContainerInterface": true`

	ipamStartStr = `,
    "ipam": {
        "type":    "host-local"`

	ipamDataDirStr = `,
        "dataDir": "%s"`

	ipamResolvConfStr = `,
		"resolvConf": "%s"`

	ipMasqConfStr = `,
	"ipMasq": %t`

	ipMasqBackendConfStr = `,
	"ipMasqBackend": "%s"`

	// Single subnet configuration (legacy)
	subnetConfStr = `,
        "subnet":  "%s"`
	gatewayConfStr = `,
        "gateway": "%s"`

	// Ranges (multiple subnets) configuration
	rangesStartStr = `,
        "ranges": [`
	rangeSubnetConfStr = `
            [{
                "subnet":  "%s"
            }]`
	rangeSubnetGWConfStr = `
            [{
                "subnet":  "%s",
                "gateway": "%s"
            }]`
	rangesEndStr = `
        ]`

	ipamEndStr = `
    }`

	macspoofchkFormat = `,
        "macspoofchk": %t`

	argsFormat = `,
    "args": {
        "cni": {
            "mac": %q
        }
    }`

	runtimeConfig = `,
    "RuntimeConfig": {
        "mac": %q
    }`
)

// netConfJSON() generates a JSON network configuration string
// for a test case.
func (tc testCase) netConfJSON(dataDir string) string {
	conf := fmt.Sprintf(netConfStr, tc.cniVersion, BRNAME)
	if tc.vlan != 0 {
		conf += fmt.Sprintf(vlan, tc.vlan)

		if tc.removeDefaultVlan {
			conf += preserveDefaultVlan
		}
	}

	if tc.isLayer2 && tc.vlanTrunk != nil {
		conf += vlanTrunkStartStr
		for i, vlan := range tc.vlanTrunk {
			if i > 0 {
				conf += ","
			}
			if vlan.ID != nil {
				conf += fmt.Sprintf(vlanTrunk, *vlan.ID)
			}
			if vlan.MinID != nil && vlan.MaxID != nil {
				conf += fmt.Sprintf(vlanTrunkRange, *vlan.MinID, *vlan.MaxID)
			}
		}
		conf += vlanTrunkEndStr
	}

	if tc.ipMasq {
		conf += tc.ipMasqConfig()
	}
	if tc.ipMasqBackend != "" {
		conf += tc.ipMasqBackendConfig()
	}
	if tc.args.cni.mac != "" {
		conf += fmt.Sprintf(argsFormat, tc.args.cni.mac)
	}
	if tc.runtimeConfig.mac != "" {
		conf += fmt.Sprintf(runtimeConfig, tc.runtimeConfig.mac)
	}
	if tc.macspoofchk {
		conf += fmt.Sprintf(macspoofchkFormat, tc.macspoofchk)
	}

	if tc.disableContIface {
		conf += disableContainerInterface
	}

	if !tc.isLayer2 {
		conf += netDefault
		if tc.subnet != "" || tc.ranges != nil {
			conf += ipamStartStr
			if dataDir != "" {
				conf += fmt.Sprintf(ipamDataDirStr, dataDir)
			}
			if tc.subnet != "" {
				conf += tc.subnetConfig()
			}
			if tc.ranges != nil {
				conf += tc.rangesConfig()
			}
			if tc.resolvConf != "" {
				conf += tc.resolvConfConfig()
			}
			conf += ipamEndStr
		}
	} else {
		conf += `,
	"ipam": {}`
	}
	return "{" + conf + "\n}"
}

func (tc testCase) subnetConfig() string {
	conf := fmt.Sprintf(subnetConfStr, tc.subnet)
	if tc.gateway != "" {
		conf += fmt.Sprintf(gatewayConfStr, tc.gateway)
	}
	return conf
}

func (tc testCase) ipMasqConfig() string {
	conf := fmt.Sprintf(ipMasqConfStr, tc.ipMasq)
	return conf
}

func (tc testCase) ipMasqBackendConfig() string {
	conf := fmt.Sprintf(ipMasqBackendConfStr, tc.ipMasqBackend)
	return conf
}

func (tc testCase) rangesConfig() string {
	conf := rangesStartStr
	for i, tcRange := range tc.ranges {
		if i > 0 {
			conf += ","
		}
		if tcRange.gateway != "" {
			conf += fmt.Sprintf(rangeSubnetGWConfStr, tcRange.subnet, tcRange.gateway)
		} else {
			conf += fmt.Sprintf(rangeSubnetConfStr, tcRange.subnet)
		}
	}
	return conf + rangesEndStr
}

func (tc testCase) resolvConfConfig() string {
	conf := fmt.Sprintf(ipamResolvConfStr, tc.resolvConf)
	return conf
}

func newResolvConf() (string, error) {
	f, err := os.CreateTemp("", "host_local_resolv")
	if err != nil {
		return "", err
	}
	defer f.Close()
	name := f.Name()
	_, err = f.WriteString(fmt.Sprintf("nameserver %s", NAMESERVER))
	return name, err
}

func deleteResolvConf(path string) error {
	return os.Remove(path)
}

var counter uint

// createCmdArgs generates network configuration and creates command
// arguments for a test case.
func (tc testCase) createCmdArgs(targetNS ns.NetNS, dataDir string) *skel.CmdArgs {
	conf := tc.netConfJSON(dataDir)
	// defer func() { counter += 1 }()
	return &skel.CmdArgs{
		ContainerID: fmt.Sprintf("dummy-%d", counter),
		Netns:       targetNS.Path(),
		IfName:      IFNAME,
		StdinData:   []byte(conf),
		Args:        tc.envArgs,
	}
}

// createCheckCmdArgs generates network configuration and creates command
// arguments for a Check test case.
func (tc testCase) createCheckCmdArgs(targetNS ns.NetNS, config *Net) *skel.CmdArgs {
	conf, err := json.Marshal(config)
	Expect(err).NotTo(HaveOccurred())

	// TODO Don't we need to use the same counter as before?
	// defer func() { counter += 1 }()
	return &skel.CmdArgs{
		ContainerID: fmt.Sprintf("dummy-%d", counter),
		Netns:       targetNS.Path(),
		IfName:      IFNAME,
		StdinData:   conf,
	}
}

// expectedCIDRs determines the IPv4 and IPv6 CIDRs in which the resulting
// addresses are expected to be contained.
func (tc testCase) expectedCIDRs() ([]*net.IPNet, []*net.IPNet) {
	var cidrsV4, cidrsV6 []*net.IPNet
	appendSubnet := func(subnet string) {
		ip, cidr, err := net.ParseCIDR(subnet)
		Expect(err).NotTo(HaveOccurred())
		if ipVersion(ip) == "4" {
			cidrsV4 = append(cidrsV4, cidr)
		} else {
			cidrsV6 = append(cidrsV6, cidr)
		}
	}
	if tc.subnet != "" {
		appendSubnet(tc.subnet)
	}
	for _, r := range tc.ranges {
		appendSubnet(r.subnet)
	}
	return cidrsV4, cidrsV6
}

// delBridgeAddrs() deletes addresses from the bridge
func delBridgeAddrs(testNS ns.NetNS) {
	err := testNS.Do(func(ns.NetNS) error {
		defer GinkgoRecover()

		br, err := netlink.LinkByName(BRNAME)
		Expect(err).NotTo(HaveOccurred())
		addrs, err := netlink.AddrList(br, netlink.FAMILY_ALL)
		Expect(err).NotTo(HaveOccurred())
		for _, addr := range addrs {
			if !addr.IP.IsLinkLocalUnicast() {
				err = netlink.AddrDel(br, &addr)
				Expect(err).NotTo(HaveOccurred())
			}
		}

		br, err = netlink.LinkByName(BRNAMEVLAN)
		if err == nil {
			addrs, err = netlink.AddrList(br, netlink.FAMILY_ALL)
			Expect(err).NotTo(HaveOccurred())
			for _, addr := range addrs {
				if !addr.IP.IsLinkLocalUnicast() {
					err = netlink.AddrDel(br, &addr)
					Expect(err).NotTo(HaveOccurred())
				}
			}
		}

		return nil
	})
	Expect(err).NotTo(HaveOccurred())
}

func delVlanAddrs(testNS ns.NetNS, vlan int) {
	err := testNS.Do(func(ns.NetNS) error {
		defer GinkgoRecover()

		vlanLink, err := netlink.LinkByName(fmt.Sprintf("%s.%d", BRNAME, vlan))
		Expect(err).NotTo(HaveOccurred())
		addrs, err := netlink.AddrList(vlanLink, netlink.FAMILY_ALL)
		Expect(err).NotTo(HaveOccurred())
		for _, addr := range addrs {
			if !addr.IP.IsLinkLocalUnicast() {
				err = netlink.AddrDel(vlanLink, &addr)
				Expect(err).NotTo(HaveOccurred())
			}
		}

		return nil
	})
	Expect(err).NotTo(HaveOccurred())
}

func ipVersion(ip net.IP) string {
	if ip.To4() != nil {
		return "4"
	}
	return "6"
}

func countIPAMIPs(path string) (int, error) {
	count := 0
	entries, err := os.ReadDir(path)
	if err != nil {
		return -1, err
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		if net.ParseIP(entry.Name()) != nil {
			count++
		}
	}
	return count, nil
}

func checkVlan(vlanID int, bridgeVlanInfo []*nl.BridgeVlanInfo) bool {
	for _, vlan := range bridgeVlanInfo {
		if vlan.Vid == uint16(vlanID) {
			return true
		}
	}

	return false
}

type cmdAddDelTester interface {
	cmdAddTest(tc testCase, dataDir string) (types.Result, error)
	cmdCheckTest(tc testCase, conf *Net, dataDir string)
	cmdDelTest(tc testCase, dataDir string)
}

type testerBase struct {
	testNS   ns.NetNS
	targetNS ns.NetNS
	args     *skel.CmdArgs
	vethName string
}

type (
	testerV10x      testerBase
	testerV04x      testerBase
	testerV03x      testerBase
	testerV01xOr02x testerBase
)

func newTesterByVersion(version string, testNS, targetNS ns.NetNS) cmdAddDelTester {
	switch {
	case strings.HasPrefix(version, "1.0."):
		return &testerV10x{
			testNS:   testNS,
			targetNS: targetNS,
		}
	case strings.HasPrefix(version, "0.4."):
		return &testerV04x{
			testNS:   testNS,
			targetNS: targetNS,
		}
	case strings.HasPrefix(version, "0.3."):
		return &testerV03x{
			testNS:   testNS,
			targetNS: targetNS,
		}
	default:
		return &testerV01xOr02x{
			testNS:   testNS,
			targetNS: targetNS,
		}
	}
}

func (tester *testerV10x) cmdAddTest(tc testCase, dataDir string) (types.Result, error) {
	// Generate network config and command arguments
	tester.args = tc.createCmdArgs(tester.targetNS, dataDir)

	// Execute cmdADD on the plugin
	var result *types100.Result
	err := tester.testNS.Do(func(ns.NetNS) error {
		defer GinkgoRecover()

		r, raw, err := testutils.CmdAddWithArgs(tester.args, func() error {
			return cmdAdd(tester.args)
		})
		Expect(err).NotTo(HaveOccurred())
		Expect(strings.Index(string(raw), "\"interfaces\":")).Should(BeNumerically(">", 0))

		resultType, err := r.GetAsVersion(tc.cniVersion)
		Expect(err).NotTo(HaveOccurred())
		result = resultType.(*types100.Result)

		if !tc.isLayer2 && tc.vlan != 0 {
			Expect(result.Interfaces).To(HaveLen(4))
		} else {
			Expect(result.Interfaces).To(HaveLen(3))
		}

		Expect(result.Interfaces[0].Name).To(Equal(BRNAME))
		Expect(result.Interfaces[0].Mac).To(HaveLen(17))

		Expect(result.Interfaces[1].Name).To(HavePrefix("veth"))
		Expect(result.Interfaces[1].Mac).To(HaveLen(17))

		Expect(result.Interfaces[2].Name).To(Equal(IFNAME))
		Expect(result.Interfaces[2].Mac).To(HaveLen(17))
		if tc.expectedMac != "" {
			Expect(result.Interfaces[2].Mac).To(Equal(tc.expectedMac))
		}
		Expect(result.Interfaces[2].Sandbox).To(Equal(tester.targetNS.Path()))

		// Make sure bridge link exists
		link, err := netlink.LinkByName(result.Interfaces[0].Name)
		Expect(err).NotTo(HaveOccurred())
		Expect(link.Attrs().Name).To(Equal(BRNAME))
		Expect(link).To(BeAssignableToTypeOf(&netlink.Bridge{}))
		Expect(link.Attrs().HardwareAddr.String()).To(Equal(result.Interfaces[0].Mac))
		bridgeMAC := link.Attrs().HardwareAddr.String()

		var vlanLink netlink.Link
		if !tc.isLayer2 && tc.vlan != 0 {
			// Make sure vlan link exists
			vlanLink, err = netlink.LinkByName(fmt.Sprintf("%s.%d", BRNAME, tc.vlan))
			Expect(err).NotTo(HaveOccurred())
			Expect(vlanLink.Attrs().Name).To(Equal(fmt.Sprintf("%s.%d", BRNAME, tc.vlan)))
			Expect(vlanLink).To(BeAssignableToTypeOf(&netlink.Veth{}))

			// Check the bridge dot vlan interface have the vlan tag
			peerLink, err := netlink.LinkByIndex(vlanLink.Attrs().Index - 1)
			Expect(err).NotTo(HaveOccurred())
			interfaceMap, err := netlink.BridgeVlanList()
			Expect(err).NotTo(HaveOccurred())
			vlans, isExist := interfaceMap[int32(peerLink.Attrs().Index)]
			Expect(isExist).To(BeTrue())
			Expect(checkVlan(tc.vlan, vlans)).To(BeTrue())
			if tc.removeDefaultVlan {
				Expect(vlans).To(HaveLen(1))
			}
		}

		// Check the bridge vlan filtering equals true
		if tc.vlan != 0 || tc.vlanTrunk != nil {
			Expect(*link.(*netlink.Bridge).VlanFiltering).To(BeTrue())
		} else {
			Expect(*link.(*netlink.Bridge).VlanFiltering).To(BeFalse())
		}

		// Ensure bridge has expected gateway address(es)
		var addrs []netlink.Addr
		if tc.vlan == 0 {
			addrs, err = netlink.AddrList(link, netlink.FAMILY_ALL)
		} else {
			addrs, err = netlink.AddrList(vlanLink, netlink.FAMILY_ALL)
		}
		Expect(err).NotTo(HaveOccurred())
		Expect(addrs).ToNot(BeEmpty())
		for _, cidr := range tc.expGWCIDRs {
			ip, subnet, err := net.ParseCIDR(cidr)
			Expect(err).NotTo(HaveOccurred())

			found := false
			subnetPrefix, subnetBits := subnet.Mask.Size()
			for _, a := range addrs {
				aPrefix, aBits := a.IPNet.Mask.Size()
				if a.IPNet.IP.Equal(ip) && aPrefix == subnetPrefix && aBits == subnetBits {
					found = true
					break
				}
			}
			Expect(found).To(BeTrue(), fmt.Sprintf("failed to find %s", cidr))
		}

		// Check for the veth link in the main namespace
		links, err := netlink.LinkList()
		Expect(err).NotTo(HaveOccurred())
		if !tc.isLayer2 && tc.vlan != 0 {
			Expect(links).To(HaveLen(5)) // Bridge, Bridge vlan veth, veth, and loopback
		} else {
			Expect(links).To(HaveLen(3)) // Bridge, veth, and loopback
		}

		link, err = netlink.LinkByName(result.Interfaces[1].Name)
		Expect(err).NotTo(HaveOccurred())
		Expect(link).To(BeAssignableToTypeOf(&netlink.Veth{}))
		tester.vethName = result.Interfaces[1].Name

		// check vlan exist on the veth interface
		if tc.vlan != 0 {
			interfaceMap, err := netlink.BridgeVlanList()
			Expect(err).NotTo(HaveOccurred())
			vlans, isExist := interfaceMap[int32(link.Attrs().Index)]
			Expect(isExist).To(BeTrue())
			Expect(checkVlan(tc.vlan, vlans)).To(BeTrue())
			if tc.removeDefaultVlan {
				Expect(vlans).To(HaveLen(1))
			}
		}

		// check VlanTrunks exist on the veth interface
		if tc.vlanTrunk != nil {
			interfaceMap, err := netlink.BridgeVlanList()
			Expect(err).NotTo(HaveOccurred())
			vlans, isExist := interfaceMap[int32(link.Attrs().Index)]
			Expect(isExist).To(BeTrue())

			for _, vlanEntry := range tc.vlanTrunk {
				if vlanEntry.ID != nil {
					Expect(checkVlan(*vlanEntry.ID, vlans)).To(BeTrue())
				}
				if vlanEntry.MinID != nil && vlanEntry.MaxID != nil {
					for vid := *vlanEntry.MinID; vid <= *vlanEntry.MaxID; vid++ {
						Expect(checkVlan(vid, vlans)).To(BeTrue())
					}
				}
			}
		}

		// Check that the bridge has a different mac from the veth
		// If not, it means the bridge has an unstable mac and will change
		// as ifs are added and removed
		// this check is not relevant for a layer 2 bridge
		if !tc.isLayer2 && tc.vlan == 0 {
			Expect(link.Attrs().HardwareAddr.String()).NotTo(Equal(bridgeMAC))
		}

		// Check that resolvConf was used properly
		if !tc.isLayer2 && tc.resolvConf != "" {
			Expect(result.DNS.Nameservers).To(Equal([]string{NAMESERVER}))
		}

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
		assertContainerInterfaceLinkState(&tc, link)

		expCIDRsV4, expCIDRsV6 := tc.expectedCIDRs()
		addrs, err := netlink.AddrList(link, netlink.FAMILY_V4)
		Expect(err).NotTo(HaveOccurred())
		Expect(addrs).To(HaveLen(len(expCIDRsV4)))
		addrs, err = netlink.AddrList(link, netlink.FAMILY_V6)
		Expect(err).NotTo(HaveOccurred())
		assertIPv6Addresses(&tc, addrs, expCIDRsV6)

		// Ignore link local address which may or may not be
		// ready when we read addresses.
		var foundAddrs int
		for _, addr := range addrs {
			if !addr.IP.IsLinkLocalUnicast() {
				foundAddrs++
			}
		}
		Expect(foundAddrs).To(Equal(len(expCIDRsV6)))

		// Ensure the default route(s)
		routes, err := netlink.RouteList(link, 0)
		Expect(err).NotTo(HaveOccurred())

		var defaultRouteFound4, defaultRouteFound6 bool
		for _, cidr := range tc.expGWCIDRs {
			gwIP, _, err := net.ParseCIDR(cidr)
			Expect(err).NotTo(HaveOccurred())
			var found *bool
			if ipVersion(gwIP) == "4" {
				found = &defaultRouteFound4
			} else {
				found = &defaultRouteFound6
			}
			if *found == true {
				continue
			}
			for _, route := range routes {
				*found = (route.Dst == nil && route.Src == nil && route.Gw.Equal(gwIP))
				if *found {
					break
				}
			}
			Expect(*found).To(BeTrue())
		}

		return nil
	})
	Expect(err).NotTo(HaveOccurred())

	return result, nil
}

func assertContainerInterfaceLinkState(tc *testCase, link netlink.Link) {
	linkState := int(link.Attrs().OperState)
	if tc.disableContIface {
		Expect(linkState).ToNot(Equal(netlink.OperUp))
	} else {
		Expect(linkState).To(Equal(netlink.OperUp))
	}
}

func (tester *testerV10x) cmdCheckTest(tc testCase, conf *Net, _ string) {
	// Generate network config and command arguments
	tester.args = tc.createCheckCmdArgs(tester.targetNS, conf)

	// Execute cmdCHECK on the plugin
	err := tester.testNS.Do(func(ns.NetNS) error {
		defer GinkgoRecover()

		err := testutils.CmdCheckWithArgs(tester.args, func() error {
			return cmdCheck(tester.args)
		})
		Expect(err).NotTo(HaveOccurred())

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

		expCIDRsV4, expCIDRsV6 := tc.expectedCIDRs()
		addrs, err := netlink.AddrList(link, netlink.FAMILY_V4)
		Expect(err).NotTo(HaveOccurred())
		Expect(addrs).To(HaveLen(len(expCIDRsV4)))
		addrs, err = netlink.AddrList(link, netlink.FAMILY_V6)
		Expect(addrs).To(HaveLen(len(expCIDRsV6) + 1)) // add one for the link-local
		Expect(err).NotTo(HaveOccurred())
		// Ignore link local address which may or may not be
		// ready when we read addresses.
		var foundAddrs int
		for _, addr := range addrs {
			if !addr.IP.IsLinkLocalUnicast() {
				foundAddrs++
			}
		}
		Expect(foundAddrs).To(Equal(len(expCIDRsV6)))

		// Ensure the default route(s)
		routes, err := netlink.RouteList(link, 0)
		Expect(err).NotTo(HaveOccurred())

		var defaultRouteFound4, defaultRouteFound6 bool
		for _, cidr := range tc.expGWCIDRs {
			gwIP, _, err := net.ParseCIDR(cidr)
			Expect(err).NotTo(HaveOccurred())
			var found *bool
			if ipVersion(gwIP) == "4" {
				found = &defaultRouteFound4
			} else {
				found = &defaultRouteFound6
			}
			if *found == true {
				continue
			}
			for _, route := range routes {
				*found = (route.Dst == nil && route.Src == nil && route.Gw.Equal(gwIP))
				if *found {
					break
				}
			}
			Expect(*found).To(BeTrue())
		}

		return nil
	})
	Expect(err).NotTo(HaveOccurred())
}

func (tester *testerV10x) cmdDelTest(tc testCase, dataDir string) {
	tester.args = tc.createCmdArgs(tester.targetNS, dataDir)
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
	Expect(err).NotTo(HaveOccurred())
}

func (tester *testerV04x) cmdAddTest(tc testCase, dataDir string) (types.Result, error) {
	// Generate network config and command arguments
	tester.args = tc.createCmdArgs(tester.targetNS, dataDir)

	// Execute cmdADD on the plugin
	var result *types040.Result
	err := tester.testNS.Do(func(ns.NetNS) error {
		defer GinkgoRecover()

		r, raw, err := testutils.CmdAddWithArgs(tester.args, func() error {
			return cmdAdd(tester.args)
		})
		Expect(err).NotTo(HaveOccurred())
		Expect(strings.Index(string(raw), "\"interfaces\":")).Should(BeNumerically(">", 0))

		resultType, err := r.GetAsVersion(tc.cniVersion)
		Expect(err).NotTo(HaveOccurred())
		result = resultType.(*types040.Result)

		if !tc.isLayer2 && tc.vlan != 0 {
			Expect(result.Interfaces).To(HaveLen(4))
		} else {
			Expect(result.Interfaces).To(HaveLen(3))
		}

		Expect(result.Interfaces[0].Name).To(Equal(BRNAME))
		Expect(result.Interfaces[0].Mac).To(HaveLen(17))

		Expect(result.Interfaces[1].Name).To(HavePrefix("veth"))
		Expect(result.Interfaces[1].Mac).To(HaveLen(17))

		Expect(result.Interfaces[2].Name).To(Equal(IFNAME))
		Expect(result.Interfaces[2].Mac).To(HaveLen(17))
		if tc.expectedMac != "" {
			Expect(result.Interfaces[2].Mac).To(Equal(tc.expectedMac))
		}
		Expect(result.Interfaces[2].Sandbox).To(Equal(tester.targetNS.Path()))

		// Make sure bridge link exists
		link, err := netlink.LinkByName(result.Interfaces[0].Name)
		Expect(err).NotTo(HaveOccurred())
		Expect(link.Attrs().Name).To(Equal(BRNAME))
		Expect(link).To(BeAssignableToTypeOf(&netlink.Bridge{}))
		Expect(link.Attrs().HardwareAddr.String()).To(Equal(result.Interfaces[0].Mac))
		bridgeMAC := link.Attrs().HardwareAddr.String()

		var vlanLink netlink.Link
		if !tc.isLayer2 && tc.vlan != 0 {
			// Make sure vlan link exists
			vlanLink, err = netlink.LinkByName(fmt.Sprintf("%s.%d", BRNAME, tc.vlan))
			Expect(err).NotTo(HaveOccurred())
			Expect(vlanLink.Attrs().Name).To(Equal(fmt.Sprintf("%s.%d", BRNAME, tc.vlan)))
			Expect(vlanLink).To(BeAssignableToTypeOf(&netlink.Veth{}))

			// Check the bridge dot vlan interface have the vlan tag
			peerLink, err := netlink.LinkByIndex(vlanLink.Attrs().Index - 1)
			Expect(err).NotTo(HaveOccurred())
			interfaceMap, err := netlink.BridgeVlanList()
			Expect(err).NotTo(HaveOccurred())
			vlans, isExist := interfaceMap[int32(peerLink.Attrs().Index)]
			Expect(isExist).To(BeTrue())
			Expect(checkVlan(tc.vlan, vlans)).To(BeTrue())
			if tc.removeDefaultVlan {
				Expect(vlans).To(HaveLen(1))
			}
		}

		// Check the bridge vlan filtering equals true
		if tc.vlan != 0 || tc.vlanTrunk != nil {
			Expect(*link.(*netlink.Bridge).VlanFiltering).To(BeTrue())
		} else {
			Expect(*link.(*netlink.Bridge).VlanFiltering).To(BeFalse())
		}

		// Ensure bridge has expected gateway address(es)
		var addrs []netlink.Addr
		if tc.vlan == 0 {
			addrs, err = netlink.AddrList(link, netlink.FAMILY_ALL)
		} else {
			addrs, err = netlink.AddrList(vlanLink, netlink.FAMILY_ALL)
		}
		Expect(err).NotTo(HaveOccurred())
		Expect(addrs).ToNot(BeEmpty())
		for _, cidr := range tc.expGWCIDRs {
			ip, subnet, err := net.ParseCIDR(cidr)
			Expect(err).NotTo(HaveOccurred())

			found := false
			subnetPrefix, subnetBits := subnet.Mask.Size()
			for _, a := range addrs {
				aPrefix, aBits := a.IPNet.Mask.Size()
				if a.IPNet.IP.Equal(ip) && aPrefix == subnetPrefix && aBits == subnetBits {
					found = true
					break
				}
			}
			Expect(found).To(BeTrue())
		}

		// Check for the veth link in the main namespace
		links, err := netlink.LinkList()
		Expect(err).NotTo(HaveOccurred())
		if !tc.isLayer2 && tc.vlan != 0 {
			Expect(links).To(HaveLen(5)) // Bridge, Bridge vlan veth, veth, and loopback
		} else {
			Expect(links).To(HaveLen(3)) // Bridge, veth, and loopback
		}

		link, err = netlink.LinkByName(result.Interfaces[1].Name)
		Expect(err).NotTo(HaveOccurred())
		Expect(link).To(BeAssignableToTypeOf(&netlink.Veth{}))
		tester.vethName = result.Interfaces[1].Name

		// check vlan exist on the veth interface
		if tc.vlan != 0 {
			interfaceMap, err := netlink.BridgeVlanList()
			Expect(err).NotTo(HaveOccurred())
			vlans, isExist := interfaceMap[int32(link.Attrs().Index)]
			Expect(isExist).To(BeTrue())
			Expect(checkVlan(tc.vlan, vlans)).To(BeTrue())
			if tc.removeDefaultVlan {
				Expect(vlans).To(HaveLen(1))
			}
		}

		// check VlanTrunks exist on the veth interface
		if tc.vlanTrunk != nil {
			interfaceMap, err := netlink.BridgeVlanList()
			Expect(err).NotTo(HaveOccurred())
			vlans, isExist := interfaceMap[int32(link.Attrs().Index)]
			Expect(isExist).To(BeTrue())

			for _, vlanEntry := range tc.vlanTrunk {
				if vlanEntry.ID != nil {
					Expect(checkVlan(*vlanEntry.ID, vlans)).To(BeTrue())
				}
				if vlanEntry.MinID != nil && vlanEntry.MaxID != nil {
					for vid := *vlanEntry.MinID; vid <= *vlanEntry.MaxID; vid++ {
						Expect(checkVlan(vid, vlans)).To(BeTrue())
					}
				}
			}
		}

		// Check that the bridge has a different mac from the veth
		// If not, it means the bridge has an unstable mac and will change
		// as ifs are added and removed
		// this check is not relevant for a layer 2 bridge
		if !tc.isLayer2 && tc.vlan == 0 {
			Expect(link.Attrs().HardwareAddr.String()).NotTo(Equal(bridgeMAC))
		}

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

		expCIDRsV4, expCIDRsV6 := tc.expectedCIDRs()
		addrs, err := netlink.AddrList(link, netlink.FAMILY_V4)
		Expect(err).NotTo(HaveOccurred())
		Expect(addrs).To(HaveLen(len(expCIDRsV4)))
		addrs, err = netlink.AddrList(link, netlink.FAMILY_V6)
		Expect(err).NotTo(HaveOccurred())
		assertIPv6Addresses(&tc, addrs, expCIDRsV6)

		// Ignore link local address which may or may not be
		// ready when we read addresses.
		var foundAddrs int
		for _, addr := range addrs {
			if !addr.IP.IsLinkLocalUnicast() {
				foundAddrs++
			}
		}
		Expect(foundAddrs).To(Equal(len(expCIDRsV6)))

		// Ensure the default route(s)
		routes, err := netlink.RouteList(link, 0)
		Expect(err).NotTo(HaveOccurred())

		var defaultRouteFound4, defaultRouteFound6 bool
		for _, cidr := range tc.expGWCIDRs {
			gwIP, _, err := net.ParseCIDR(cidr)
			Expect(err).NotTo(HaveOccurred())
			var found *bool
			if ipVersion(gwIP) == "4" {
				found = &defaultRouteFound4
			} else {
				found = &defaultRouteFound6
			}
			if *found == true {
				continue
			}
			for _, route := range routes {
				*found = (route.Dst == nil && route.Src == nil && route.Gw.Equal(gwIP))
				if *found {
					break
				}
			}
			Expect(*found).To(BeTrue())
		}

		return nil
	})
	Expect(err).NotTo(HaveOccurred())

	return result, nil
}

func assertIPv6Addresses(tc *testCase, addrs []netlink.Addr, expCIDRsV6 []*net.IPNet) {
	if tc.disableContIface {
		Expect(addrs).To(BeEmpty())
	} else {
		Expect(addrs).To(HaveLen(len(expCIDRsV6) + 1)) // add one for the link-local
	}
}

func (tester *testerV04x) cmdCheckTest(tc testCase, conf *Net, _ string) {
	// Generate network config and command arguments
	tester.args = tc.createCheckCmdArgs(tester.targetNS, conf)

	// Execute cmdCHECK on the plugin
	err := tester.testNS.Do(func(ns.NetNS) error {
		defer GinkgoRecover()

		err := testutils.CmdCheckWithArgs(tester.args, func() error {
			return cmdCheck(tester.args)
		})
		Expect(err).NotTo(HaveOccurred())

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

		expCIDRsV4, expCIDRsV6 := tc.expectedCIDRs()
		addrs, err := netlink.AddrList(link, netlink.FAMILY_V4)
		Expect(err).NotTo(HaveOccurred())
		Expect(addrs).To(HaveLen(len(expCIDRsV4)))
		addrs, err = netlink.AddrList(link, netlink.FAMILY_V6)
		Expect(addrs).To(HaveLen(len(expCIDRsV6) + 1)) // add one for the link-local
		Expect(err).NotTo(HaveOccurred())
		// Ignore link local address which may or may not be
		// ready when we read addresses.
		var foundAddrs int
		for _, addr := range addrs {
			if !addr.IP.IsLinkLocalUnicast() {
				foundAddrs++
			}
		}
		Expect(foundAddrs).To(Equal(len(expCIDRsV6)))

		// Ensure the default route(s)
		routes, err := netlink.RouteList(link, 0)
		Expect(err).NotTo(HaveOccurred())

		var defaultRouteFound4, defaultRouteFound6 bool
		for _, cidr := range tc.expGWCIDRs {
			gwIP, _, err := net.ParseCIDR(cidr)
			Expect(err).NotTo(HaveOccurred())
			var found *bool
			if ipVersion(gwIP) == "4" {
				found = &defaultRouteFound4
			} else {
				found = &defaultRouteFound6
			}
			if *found == true {
				continue
			}
			for _, route := range routes {
				*found = (route.Dst == nil && route.Src == nil && route.Gw.Equal(gwIP))
				if *found {
					break
				}
			}
			Expect(*found).To(BeTrue())
		}

		return nil
	})
	Expect(err).NotTo(HaveOccurred())
}

func (tester *testerV04x) cmdDelTest(tc testCase, dataDir string) {
	tester.args = tc.createCmdArgs(tester.targetNS, dataDir)
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
	Expect(err).NotTo(HaveOccurred())
}

func (tester *testerV03x) cmdAddTest(tc testCase, dataDir string) (types.Result, error) {
	// Generate network config and command arguments
	tester.args = tc.createCmdArgs(tester.targetNS, dataDir)

	// Execute cmdADD on the plugin
	var result *types040.Result
	err := tester.testNS.Do(func(ns.NetNS) error {
		defer GinkgoRecover()

		r, raw, err := testutils.CmdAddWithArgs(tester.args, func() error {
			return cmdAdd(tester.args)
		})
		Expect(err).NotTo(HaveOccurred())
		Expect(strings.Index(string(raw), "\"interfaces\":")).Should(BeNumerically(">", 0))

		resultType, err := r.GetAsVersion(tc.cniVersion)
		Expect(err).NotTo(HaveOccurred())
		result = resultType.(*types040.Result)

		if !tc.isLayer2 && tc.vlan != 0 {
			Expect(result.Interfaces).To(HaveLen(4))
		} else {
			Expect(result.Interfaces).To(HaveLen(3))
		}

		Expect(result.Interfaces[0].Name).To(Equal(BRNAME))
		Expect(result.Interfaces[0].Mac).To(HaveLen(17))

		Expect(result.Interfaces[1].Name).To(HavePrefix("veth"))
		Expect(result.Interfaces[1].Mac).To(HaveLen(17))

		Expect(result.Interfaces[2].Name).To(Equal(IFNAME))
		Expect(result.Interfaces[2].Mac).To(HaveLen(17))
		if tc.expectedMac != "" {
			Expect(result.Interfaces[2].Mac).To(Equal(tc.expectedMac))
		}
		Expect(result.Interfaces[2].Sandbox).To(Equal(tester.targetNS.Path()))

		// Make sure bridge link exists
		link, err := netlink.LinkByName(result.Interfaces[0].Name)
		Expect(err).NotTo(HaveOccurred())
		Expect(link.Attrs().Name).To(Equal(BRNAME))
		Expect(link).To(BeAssignableToTypeOf(&netlink.Bridge{}))
		Expect(link.Attrs().HardwareAddr.String()).To(Equal(result.Interfaces[0].Mac))
		bridgeMAC := link.Attrs().HardwareAddr.String()

		var vlanLink netlink.Link
		if !tc.isLayer2 && tc.vlan != 0 {
			// Make sure vlan link exists
			vlanLink, err = netlink.LinkByName(fmt.Sprintf("%s.%d", BRNAME, tc.vlan))
			Expect(err).NotTo(HaveOccurred())
			Expect(vlanLink.Attrs().Name).To(Equal(fmt.Sprintf("%s.%d", BRNAME, tc.vlan)))
			Expect(vlanLink).To(BeAssignableToTypeOf(&netlink.Veth{}))

			// Check the bridge dot vlan interface have the vlan tag
			peerLink, err := netlink.LinkByIndex(vlanLink.Attrs().Index - 1)
			Expect(err).NotTo(HaveOccurred())
			interfaceMap, err := netlink.BridgeVlanList()
			Expect(err).NotTo(HaveOccurred())
			vlans, isExist := interfaceMap[int32(peerLink.Attrs().Index)]
			Expect(isExist).To(BeTrue())
			Expect(checkVlan(tc.vlan, vlans)).To(BeTrue())
			if tc.removeDefaultVlan {
				Expect(vlans).To(HaveLen(1))
			}
		}

		// Check the bridge vlan filtering equals true
		if tc.vlan != 0 || tc.vlanTrunk != nil {
			Expect(*link.(*netlink.Bridge).VlanFiltering).To(BeTrue())
		} else {
			Expect(*link.(*netlink.Bridge).VlanFiltering).To(BeFalse())
		}

		// Ensure bridge has expected gateway address(es)
		var addrs []netlink.Addr
		if tc.vlan == 0 {
			addrs, err = netlink.AddrList(link, netlink.FAMILY_ALL)
		} else {
			addrs, err = netlink.AddrList(vlanLink, netlink.FAMILY_ALL)
		}
		Expect(err).NotTo(HaveOccurred())
		Expect(addrs).ToNot(BeEmpty())
		for _, cidr := range tc.expGWCIDRs {
			ip, subnet, err := net.ParseCIDR(cidr)
			Expect(err).NotTo(HaveOccurred())

			found := false
			subnetPrefix, subnetBits := subnet.Mask.Size()
			for _, a := range addrs {
				aPrefix, aBits := a.IPNet.Mask.Size()
				if a.IPNet.IP.Equal(ip) && aPrefix == subnetPrefix && aBits == subnetBits {
					found = true
					break
				}
			}
			Expect(found).To(BeTrue())
		}

		// Check for the veth link in the main namespace
		links, err := netlink.LinkList()
		Expect(err).NotTo(HaveOccurred())
		if !tc.isLayer2 && tc.vlan != 0 {
			Expect(links).To(HaveLen(5)) // Bridge, Bridge vlan veth, veth, and loopback
		} else {
			Expect(links).To(HaveLen(3)) // Bridge, veth, and loopback
		}

		link, err = netlink.LinkByName(result.Interfaces[1].Name)
		Expect(err).NotTo(HaveOccurred())
		Expect(link).To(BeAssignableToTypeOf(&netlink.Veth{}))
		tester.vethName = result.Interfaces[1].Name

		// check vlan exist on the veth interface
		if tc.vlan != 0 {
			interfaceMap, err := netlink.BridgeVlanList()
			Expect(err).NotTo(HaveOccurred())
			vlans, isExist := interfaceMap[int32(link.Attrs().Index)]
			Expect(isExist).To(BeTrue())
			Expect(checkVlan(tc.vlan, vlans)).To(BeTrue())
			if tc.removeDefaultVlan {
				Expect(vlans).To(HaveLen(1))
			}
		}

		// check VlanTrunks exist on the veth interface
		if tc.vlanTrunk != nil {
			interfaceMap, err := netlink.BridgeVlanList()
			Expect(err).NotTo(HaveOccurred())
			vlans, isExist := interfaceMap[int32(link.Attrs().Index)]
			Expect(isExist).To(BeTrue())

			for _, vlanEntry := range tc.vlanTrunk {
				if vlanEntry.ID != nil {
					Expect(checkVlan(*vlanEntry.ID, vlans)).To(BeTrue())
				}
				if vlanEntry.MinID != nil && vlanEntry.MaxID != nil {
					for vid := *vlanEntry.MinID; vid <= *vlanEntry.MaxID; vid++ {
						Expect(checkVlan(vid, vlans)).To(BeTrue())
					}
				}
			}
		}

		// Check that the bridge has a different mac from the veth
		// If not, it means the bridge has an unstable mac and will change
		// as ifs are added and removed
		// this check is not relevant for a layer 2 bridge
		if !tc.isLayer2 && tc.vlan == 0 {
			Expect(link.Attrs().HardwareAddr.String()).NotTo(Equal(bridgeMAC))
		}

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

		expCIDRsV4, expCIDRsV6 := tc.expectedCIDRs()
		addrs, err := netlink.AddrList(link, netlink.FAMILY_V4)
		Expect(err).NotTo(HaveOccurred())
		Expect(addrs).To(HaveLen(len(expCIDRsV4)))
		addrs, err = netlink.AddrList(link, netlink.FAMILY_V6)
		Expect(err).NotTo(HaveOccurred())
		// Ignore link local address which may or may not be
		// ready when we read addresses.
		var foundAddrs int
		for _, addr := range addrs {
			if !addr.IP.IsLinkLocalUnicast() {
				foundAddrs++
			}
		}
		Expect(foundAddrs).To(Equal(len(expCIDRsV6)))

		// Ensure the default route(s)
		routes, err := netlink.RouteList(link, 0)
		Expect(err).NotTo(HaveOccurred())

		var defaultRouteFound4, defaultRouteFound6 bool
		for _, cidr := range tc.expGWCIDRs {
			gwIP, _, err := net.ParseCIDR(cidr)
			Expect(err).NotTo(HaveOccurred())
			var found *bool
			if ipVersion(gwIP) == "4" {
				found = &defaultRouteFound4
			} else {
				found = &defaultRouteFound6
			}
			if *found == true {
				continue
			}
			for _, route := range routes {
				*found = (route.Dst == nil && route.Src == nil && route.Gw.Equal(gwIP))
				if *found {
					break
				}
			}
			Expect(*found).To(BeTrue())
		}

		return nil
	})
	Expect(err).NotTo(HaveOccurred())
	return result, nil
}

func (tester *testerV03x) cmdCheckTest(_ testCase, _ *Net, _ string) {
}

func (tester *testerV03x) cmdDelTest(_ testCase, _ string) {
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
	Expect(err).NotTo(HaveOccurred())
}

func expect020AddError(tc testCase) bool {
	return tc.AddErr020 != "" && tc.cniVersion == "0.2.0"
}

func expect020DelError(tc testCase) bool {
	return tc.DelErr020 != "" && tc.cniVersion == "0.2.0"
}

func expect010AddError(tc testCase) bool {
	return tc.AddErr010 != "" && tc.cniVersion == "0.1.0"
}

func expect010DelError(tc testCase) bool {
	return tc.DelErr010 != "" && tc.cniVersion == "0.1.0"
}

func (tester *testerV01xOr02x) cmdAddTest(tc testCase, dataDir string) (types.Result, error) {
	// Generate network config and command arguments
	tester.args = tc.createCmdArgs(tester.targetNS, dataDir)

	var hostNSVlanMap map[int32][]*nl.BridgeVlanInfo

	// Execute cmdADD on the plugin
	err := tester.testNS.Do(func(ns.NetNS) error {
		defer GinkgoRecover()

		r, raw, err := testutils.CmdAddWithArgs(tester.args, func() error {
			return cmdAdd(tester.args)
		})

		if expect020AddError(tc) || expect010AddError(tc) {
			return err
		}
		Expect(err).NotTo(HaveOccurred())
		Expect(strings.Index(string(raw), "\"ip\":")).Should(BeNumerically(">", 0))

		// We expect a version 0.1.0 or 0.2.0 result
		_, err = r.GetAsVersion(tc.cniVersion)
		Expect(err).NotTo(HaveOccurred())

		// Make sure bridge link exists
		link, err := netlink.LinkByName(BRNAME)
		Expect(err).NotTo(HaveOccurred())
		Expect(link.Attrs().Name).To(Equal(BRNAME))
		Expect(link).To(BeAssignableToTypeOf(&netlink.Bridge{}))

		var vlanLink netlink.Link
		if !tc.isLayer2 && tc.vlan != 0 {
			// Make sure vlan link exists
			vlanLink, err = netlink.LinkByName(fmt.Sprintf("%s.%d", BRNAME, tc.vlan))
			Expect(err).NotTo(HaveOccurred())
			Expect(vlanLink.Attrs().Name).To(Equal(fmt.Sprintf("%s.%d", BRNAME, tc.vlan)))
			Expect(vlanLink).To(BeAssignableToTypeOf(&netlink.Veth{}))

			// Check the bridge dot vlan interface have the vlan tag
			peerLink, err := netlink.LinkByIndex(vlanLink.Attrs().Index - 1)
			Expect(err).NotTo(HaveOccurred())
			interfaceMap, err := netlink.BridgeVlanList()
			Expect(err).NotTo(HaveOccurred())
			vlans, isExist := interfaceMap[int32(peerLink.Attrs().Index)]
			Expect(isExist).To(BeTrue())
			Expect(checkVlan(tc.vlan, vlans)).To(BeTrue())
			if tc.removeDefaultVlan {
				Expect(vlans).To(HaveLen(1))
			}
		}

		// Check the bridge vlan filtering equals true
		if tc.vlan != 0 {
			Expect(*link.(*netlink.Bridge).VlanFiltering).To(BeTrue())
		} else {
			Expect(*link.(*netlink.Bridge).VlanFiltering).To(BeFalse())
		}

		// Ensure bridge has expected gateway address(es)
		var addrs []netlink.Addr
		if tc.vlan == 0 {
			addrs, err = netlink.AddrList(link, netlink.FAMILY_ALL)
		} else {
			addrs, err = netlink.AddrList(vlanLink, netlink.FAMILY_ALL)
		}
		Expect(err).NotTo(HaveOccurred())
		Expect(addrs).ToNot(BeEmpty())
		for _, cidr := range tc.expGWCIDRs {
			ip, subnet, err := net.ParseCIDR(cidr)
			Expect(err).NotTo(HaveOccurred())

			found := false
			subnetPrefix, subnetBits := subnet.Mask.Size()
			for _, a := range addrs {
				aPrefix, aBits := a.IPNet.Mask.Size()
				if a.IPNet.IP.Equal(ip) && aPrefix == subnetPrefix && aBits == subnetBits {
					found = true
					break
				}
			}
			Expect(found).To(BeTrue())
		}

		// Check for the veth link in the main namespace; can't
		// check the for the specific link since version 0.1.0
		// doesn't report interfaces
		links, err := netlink.LinkList()
		Expect(err).NotTo(HaveOccurred())
		if !tc.isLayer2 && tc.vlan != 0 {
			Expect(links).To(HaveLen(5)) // Bridge, Bridge vlan veth, veth, and loopback
		} else {
			Expect(links).To(HaveLen(3)) // Bridge, veth, and loopback
		}

		// Grab the vlan map in the host NS for checking later
		if tc.vlan != 0 {
			hostNSVlanMap, err = netlink.BridgeVlanList()
			Expect(err).NotTo(HaveOccurred())
		}
		return nil
	})
	if expect020AddError(tc) {
		Expect(err).To(MatchError(tc.AddErr020))
		return nil, nil
	} else if expect010AddError(tc) {
		Expect(err).To(MatchError(tc.AddErr010))
		return nil, nil
	}
	Expect(err).NotTo(HaveOccurred())

	// Find the veth peer in the container namespace and the default route
	err = tester.targetNS.Do(func(ns.NetNS) error {
		defer GinkgoRecover()

		link, err := netlink.LinkByName(IFNAME)
		Expect(err).NotTo(HaveOccurred())
		Expect(link.Attrs().Name).To(Equal(IFNAME))
		Expect(link).To(BeAssignableToTypeOf(&netlink.Veth{}))

		expCIDRsV4, expCIDRsV6 := tc.expectedCIDRs()
		addrs, err := netlink.AddrList(link, netlink.FAMILY_V4)
		Expect(err).NotTo(HaveOccurred())
		Expect(addrs).To(HaveLen(len(expCIDRsV4)))
		addrs, err = netlink.AddrList(link, netlink.FAMILY_V6)
		Expect(err).NotTo(HaveOccurred())
		// Ignore link local address which may or may not be
		// ready when we read addresses.
		var foundAddrs int
		for _, addr := range addrs {
			if !addr.IP.IsLinkLocalUnicast() {
				foundAddrs++
			}
		}
		Expect(foundAddrs).To(Equal(len(expCIDRsV6)))

		// Ensure the default route(s)
		routes, err := netlink.RouteList(link, 0)
		Expect(err).NotTo(HaveOccurred())

		var defaultRouteFound4, defaultRouteFound6 bool
		for _, cidr := range tc.expGWCIDRs {
			gwIP, _, err := net.ParseCIDR(cidr)
			Expect(err).NotTo(HaveOccurred())
			var found *bool
			if ipVersion(gwIP) == "4" {
				found = &defaultRouteFound4
			} else {
				found = &defaultRouteFound6
			}
			if *found == true {
				continue
			}
			for _, route := range routes {
				*found = (route.Dst == nil && route.Src == nil && route.Gw.Equal(gwIP))
				if *found {
					break
				}
			}
			Expect(*found).To(BeTrue())
		}

		// Validate VLAN in the host NS. Since 0.1.0/0.2.0 don't return
		// any host interface information, we have to look up the container
		// namespace veth's peer index instead
		if tc.vlan != 0 {
			_, peerIndex, err := ip.GetVethPeerIfindex(IFNAME)
			Expect(err).NotTo(HaveOccurred())
			Expect(peerIndex).To(BeNumerically(">", 0))
			vlans, isExist := hostNSVlanMap[int32(peerIndex)]
			Expect(isExist).To(BeTrue())
			Expect(checkVlan(tc.vlan, vlans)).To(BeTrue())
			if tc.removeDefaultVlan {
				Expect(vlans).To(HaveLen(1))
			}
		}

		return nil
	})
	Expect(err).NotTo(HaveOccurred())
	return nil, nil
}

func (tester *testerV01xOr02x) cmdCheckTest(_ testCase, _ *Net, _ string) {
}

func (tester *testerV01xOr02x) cmdDelTest(tc testCase, _ string) {
	err := tester.testNS.Do(func(ns.NetNS) error {
		defer GinkgoRecover()

		err := testutils.CmdDelWithArgs(tester.args, func() error {
			return cmdDel(tester.args)
		})
		switch {
		case expect020DelError(tc):
			Expect(err).To(MatchError(tc.DelErr020))
		case expect010DelError(tc):
			Expect(err).To(MatchError(tc.DelErr010))
		default:
			Expect(err).NotTo(HaveOccurred())
		}
		return nil
	})
	Expect(err).NotTo(HaveOccurred())

	// Make sure the container veth has been deleted; cannot check
	// host veth as version 0.1.0 can't report its name
	err = tester.testNS.Do(func(ns.NetNS) error {
		defer GinkgoRecover()

		link, err := netlink.LinkByName(IFNAME)
		Expect(err).To(HaveOccurred())
		Expect(link).To(BeNil())
		return nil
	})
	Expect(err).NotTo(HaveOccurred())
}

func cmdAddDelTest(origNS, targetNS ns.NetNS, tc testCase, dataDir string) {
	tester := newTesterByVersion(tc.cniVersion, origNS, targetNS)

	// Test IP allocation
	_, err := tester.cmdAddTest(tc, dataDir)
	Expect(err).NotTo(HaveOccurred())

	// Test IP Release
	tester.cmdDelTest(tc, dataDir)

	// Clean up bridge addresses for next test case
	delBridgeAddrs(origNS)
}

func buildOneConfig(name, cniVersion string, orig *Net, prevResult types.Result) (*Net, error) {
	var err error

	inject := map[string]interface{}{
		"name":       name,
		"cniVersion": cniVersion,
	}
	// Add previous plugin result
	if prevResult != nil {
		inject["prevResult"] = prevResult
	}

	// Ensure every config uses the same name and version
	config := make(map[string]interface{})
	confBytes, err := json.Marshal(orig)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(confBytes, &config)
	if err != nil {
		return nil, fmt.Errorf("unmarshal existing network bytes: %s", err)
	}

	for key, value := range inject {
		config[key] = value
	}

	newBytes, err := json.Marshal(config)
	if err != nil {
		return nil, err
	}

	conf := &Net{}
	if err := json.Unmarshal(newBytes, &conf); err != nil {
		return nil, fmt.Errorf("error parsing configuration: %s", err)
	}

	return conf, nil
}

func cmdAddDelCheckTest(origNS, targetNS ns.NetNS, tc testCase, dataDir string) {
	tester := newTesterByVersion(tc.cniVersion, origNS, targetNS)

	// Test IP allocation
	prevResult, err := tester.cmdAddTest(tc, dataDir)
	Expect(err).NotTo(HaveOccurred())

	Expect(prevResult).NotTo(BeNil())

	confString := tc.netConfJSON(dataDir)

	conf := &Net{}
	err = json.Unmarshal([]byte(confString), &conf)
	Expect(err).NotTo(HaveOccurred())

	conf.IPAM, _, err = allocator.LoadIPAMConfig([]byte(confString), "")
	Expect(err).NotTo(HaveOccurred())

	newConf, err := buildOneConfig("testConfig", tc.cniVersion, conf, prevResult)
	Expect(err).NotTo(HaveOccurred())

	// Test CHECK
	tester.cmdCheckTest(tc, newConf, dataDir)

	// Test IP Release
	tester.cmdDelTest(tc, dataDir)

	// Clean up bridge addresses for next test case
	delBridgeAddrs(origNS)

	if tc.vlan != 0 && !tc.isLayer2 {
		delVlanAddrs(origNS, tc.vlan)
	}
}

var _ = Describe("bridge Operations", func() {
	var originalNS, targetNS ns.NetNS
	var dataDir string

	BeforeEach(func() {
		// Create a new NetNS so we don't modify the host
		var err error
		originalNS, err = testutils.NewNS()
		Expect(err).NotTo(HaveOccurred())
		targetNS, err = testutils.NewNS()
		Expect(err).NotTo(HaveOccurred())

		dataDir, err = os.MkdirTemp("", "bridge_test")
		Expect(err).NotTo(HaveOccurred())

		// Do not emulate an error, each test will set this if needed
		debugPostIPAMError = nil
	})

	AfterEach(func() {
		Expect(os.RemoveAll(dataDir)).To(Succeed())
		Expect(originalNS.Close()).To(Succeed())
		Expect(testutils.UnmountNS(originalNS)).To(Succeed())
		Expect(targetNS.Close()).To(Succeed())
		Expect(testutils.UnmountNS(targetNS)).To(Succeed())
	})

	var (
		correctID      int = 10
		correctMinID   int = 100
		correctMaxID   int = 105
		incorrectMinID int = 1000
		incorrectMaxID int = 100
		overID         int = 5000
		negativeID     int = -1
	)

	DescribeTable(
		"collectVlanTrunk succeeds",
		func(vlanTrunks []*VlanTrunk, expectedVIDs []int) {
			Expect(collectVlanTrunk(vlanTrunks)).To(ConsistOf(expectedVIDs))
		},
		Entry("when provided an empty VLAN trunk configuration", []*VlanTrunk{}, nil),
		Entry("when provided a VLAN trunk configuration with both min / max range", []*VlanTrunk{
			{
				MinID: &correctMinID,
				MaxID: &correctMaxID,
			},
		}, []int{100, 101, 102, 103, 104, 105}),
		Entry("when provided a VLAN trunk configuration with id only", []*VlanTrunk{
			{
				ID: &correctID,
			},
		}, []int{10}),
		Entry("when provided a VLAN trunk configuration with id and range", []*VlanTrunk{
			{
				ID: &correctID,
			},
			{
				MinID: &correctMinID,
				MaxID: &correctMaxID,
			},
		}, []int{10, 100, 101, 102, 103, 104, 105}),
	)

	DescribeTable(
		"collectVlanTrunk failed",
		func(vlanTrunks []*VlanTrunk, expectedError error) {
			_, err := collectVlanTrunk(vlanTrunks)
			Expect(err).To(MatchError(expectedError))
		},
		Entry("when not passed the maxID", []*VlanTrunk{{MinID: &correctMinID}}, fmt.Errorf("minID and maxID should be configured simultaneously, maxID is missing")),
		Entry("when not passed the minID", []*VlanTrunk{{MaxID: &correctMaxID}}, fmt.Errorf("minID and maxID should be configured simultaneously, minID is missing")),
		Entry("when the minID is negative", []*VlanTrunk{{MinID: &negativeID, MaxID: &correctMaxID}}, fmt.Errorf("incorrect trunk minID parameter")),
		Entry("when the minID is larger than 4094", []*VlanTrunk{{MinID: &overID, MaxID: &correctMaxID}}, fmt.Errorf("incorrect trunk minID parameter")),
		Entry("when the maxID is larger than 4094", []*VlanTrunk{{MinID: &correctMinID, MaxID: &overID}}, fmt.Errorf("incorrect trunk maxID parameter")),
		Entry("when the maxID is negative", []*VlanTrunk{{MinID: &correctMinID, MaxID: &overID}}, fmt.Errorf("incorrect trunk maxID parameter")),
		Entry("when the ID is larger than 4094", []*VlanTrunk{{ID: &overID}}, fmt.Errorf("incorrect trunk id parameter")),
		Entry("when the ID is negative", []*VlanTrunk{{ID: &negativeID}}, fmt.Errorf("incorrect trunk id parameter")),
		Entry("when the maxID is smaller than minID", []*VlanTrunk{{MinID: &incorrectMinID, MaxID: &incorrectMaxID}}, fmt.Errorf("minID is greater than maxID in trunk parameter")),
	)

	for _, ver := range testutils.AllSpecVersions {
		// Redefine ver inside for scope so real value is picked up by each dynamically defined It()
		// See Gingkgo's "Patterns for dynamically generating tests" documentation.
		ver := ver

		It(fmt.Sprintf("[%s] creates a bridge", ver), func() {
			conf := testCase{cniVersion: ver}.netConf()
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

		It(fmt.Sprintf("[%s] handles an existing bridge", ver), func() {
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

				tc := testCase{cniVersion: ver, isGW: false}
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

		for i, tc := range []testCase{
			{
				// IPv4 only
				subnet:     "10.1.2.0/24",
				expGWCIDRs: []string{"10.1.2.1/24"},
			},
			{
				// IPv6 only
				subnet:     "2001:db8::0/64",
				expGWCIDRs: []string{"2001:db8::1/64"},
			},
			{
				// Dual-Stack
				ranges: []rangeInfo{
					{subnet: "192.168.0.0/24"},
					{subnet: "fd00::0/64"},
				},
				expGWCIDRs: []string{
					"192.168.0.1/24",
					"fd00::1/64",
				},
			},
			{
				// 3 Subnets (1 IPv4 and 2 IPv6 subnets)
				ranges: []rangeInfo{
					{subnet: "192.168.0.0/24"},
					{subnet: "fd00::0/64"},
					{subnet: "2001:db8::0/64"},
				},
				expGWCIDRs: []string{
					"192.168.0.1/24",
					"fd00::1/64",
					"2001:db8::1/64",
				},
				AddErr020: "CNI version 0.2.0 does not support more than 1 address per family",
				DelErr020: "CNI version 0.2.0 does not support more than 1 address per family",
				AddErr010: "CNI version 0.1.0 does not support more than 1 address per family",
				DelErr010: "CNI version 0.1.0 does not support more than 1 address per family",
			},
			{
				// with resolvConf DNS settings
				subnet:     "10.1.2.0/24",
				expGWCIDRs: []string{"10.1.2.1/24"},
				resolvConf: resolvConf,
			},
		} {
			tc := tc
			i := i
			It(fmt.Sprintf("[%s] (%d) configures and deconfigures a bridge and veth with default route with ADD/DEL", ver, i), func() {
				tc.cniVersion = ver
				cmdAddDelTest(originalNS, targetNS, tc, dataDir)
			})
		}

		It(fmt.Sprintf("[%s] configures and deconfigures a l2 bridge and veth with ADD/DEL", ver), func() {
			tc := testCase{
				cniVersion: ver,
				isLayer2:   true,
				AddErr020:  "cannot convert: no valid IP addresses",
				AddErr010:  "cannot convert: no valid IP addresses",
			}
			cmdAddDelTest(originalNS, targetNS, tc, dataDir)
		})

		It(fmt.Sprintf("[%s] configures and deconfigures a l2 bridge with vlan id 100 using ADD/DEL", ver), func() {
			tc := testCase{
				cniVersion: ver,
				isLayer2:   true,
				vlan:       100,
				AddErr020:  "cannot convert: no valid IP addresses",
				AddErr010:  "cannot convert: no valid IP addresses",
			}
			cmdAddDelTest(originalNS, targetNS, tc, dataDir)
		})

		// TODO find some way to put pointer
		It(fmt.Sprintf("[%s] configures and deconfigures a l2 bridge with vlan id 100, vlanTrunk 101,200~210 using ADD/DEL", ver), func() {
			id, minID, maxID := 101, 200, 210
			tc := testCase{
				cniVersion: ver,
				isLayer2:   true,
				vlanTrunk: []*VlanTrunk{
					{ID: &id},
					{
						MinID: &minID,
						MaxID: &maxID,
					},
				},
				AddErr020: "cannot convert: no valid IP addresses",
				AddErr010: "cannot convert: no valid IP addresses",
			}
			cmdAddDelTest(originalNS, targetNS, tc, dataDir)
		})

		It(fmt.Sprintf("[%s] configures and deconfigures a l2 bridge with vlan id 100 and no default vlan using ADD/DEL", ver), func() {
			tc := testCase{
				cniVersion:        ver,
				isLayer2:          true,
				vlan:              100,
				removeDefaultVlan: true,
				AddErr020:         "cannot convert: no valid IP addresses",
				AddErr010:         "cannot convert: no valid IP addresses",
			}
			cmdAddDelTest(originalNS, targetNS, tc, dataDir)
		})

		for i, tc := range []testCase{
			{
				// IPv4 only
				subnet:     "10.1.2.0/24",
				expGWCIDRs: []string{"10.1.2.1/24"},
				vlan:       100,
			},
			{
				// IPv6 only
				subnet:     "2001:db8::0/64",
				expGWCIDRs: []string{"2001:db8::1/64"},
				vlan:       100,
			},
			{
				// Dual-Stack
				ranges: []rangeInfo{
					{subnet: "192.168.0.0/24"},
					{subnet: "fd00::0/64"},
				},
				expGWCIDRs: []string{
					"192.168.0.1/24",
					"fd00::1/64",
				},
				vlan: 100,
			},
			{
				// 3 Subnets (1 IPv4 and 2 IPv6 subnets)
				ranges: []rangeInfo{
					{subnet: "192.168.0.0/24"},
					{subnet: "fd00::0/64"},
					{subnet: "2001:db8::0/64"},
				},
				expGWCIDRs: []string{
					"192.168.0.1/24",
					"fd00::1/64",
					"2001:db8::1/64",
				},
				vlan:      100,
				AddErr020: "CNI version 0.2.0 does not support more than 1 address per family",
				DelErr020: "CNI version 0.2.0 does not support more than 1 address per family",
				AddErr010: "CNI version 0.1.0 does not support more than 1 address per family",
				DelErr010: "CNI version 0.1.0 does not support more than 1 address per family",
			},
		} {
			tc := tc
			i := i
			It(fmt.Sprintf("[%s] (%d) configures and deconfigures a bridge, veth with default route and vlanID 100 with ADD/DEL", ver, i), func() {
				tc.cniVersion = ver
				cmdAddDelTest(originalNS, targetNS, tc, dataDir)
			})
			It(fmt.Sprintf("[%s] (%d) configures and deconfigures a bridge, veth with default route and vlanID 100 and no default vlan with ADD/DEL", ver, i), func() {
				tc.cniVersion = ver
				tc.removeDefaultVlan = true
				cmdAddDelTest(originalNS, targetNS, tc, dataDir)
			})
		}

		for i, tc := range []testCase{
			{
				// IPv4 only
				subnet:     "10.1.2.0/24",
				expGWCIDRs: []string{"10.1.2.1/24"},
			},
			{
				// IPv6 only
				subnet:     "2001:db8::0/64",
				expGWCIDRs: []string{"2001:db8::1/64"},
			},
			{
				// Dual-Stack
				ranges: []rangeInfo{
					{subnet: "192.168.0.0/24"},
					{subnet: "fd00::0/64"},
				},
				expGWCIDRs: []string{
					"192.168.0.1/24",
					"fd00::1/64",
				},
			},
		} {
			tc := tc
			i := i
			It(fmt.Sprintf("[%s] (%d) configures and deconfigures a bridge and veth with default route with ADD/DEL", ver, i), func() {
				tc.cniVersion = ver
				cmdAddDelTest(originalNS, targetNS, tc, dataDir)
			})
		}

		It("deconfigures an unconfigured bridge with DEL", func() {
			tc := testCase{
				cniVersion: ver,
				subnet:     "10.1.2.0/24",
				expGWCIDRs: []string{"10.1.2.1/24"},
			}

			tester := testerV03x{
				testNS:   originalNS,
				targetNS: targetNS,
				args:     tc.createCmdArgs(targetNS, dataDir),
			}

			// Execute cmdDEL on the plugin, expect no errors
			tester.cmdDelTest(tc, dataDir)
		})

		for i, tc := range []struct {
			gwCIDRFirst  string
			gwCIDRSecond string
		}{
			{
				// IPv4
				gwCIDRFirst:  "10.0.0.1/8",
				gwCIDRSecond: "10.1.2.3/16",
			},
			{
				// IPv6, overlapping subnets
				gwCIDRFirst:  "2001:db8:1::1/48",
				gwCIDRSecond: "2001:db8:1:2::1/64",
			},
			{
				// IPv6, non-overlapping subnets
				gwCIDRFirst:  "2001:db8:1:2::1/64",
				gwCIDRSecond: "fd00:1234::1/64",
			},
		} {
			tc := tc
			i := i
			It(fmt.Sprintf("[%s] (%d) ensure bridge address", ver, i), func() {
				conf := testCase{cniVersion: ver, isGW: true}.netConf()

				gwIP, gwSubnet, err := net.ParseCIDR(tc.gwCIDRFirst)
				Expect(err).NotTo(HaveOccurred())
				gwnFirst := net.IPNet{IP: gwIP, Mask: gwSubnet.Mask}
				gwIP, gwSubnet, err = net.ParseCIDR(tc.gwCIDRSecond)
				Expect(err).NotTo(HaveOccurred())
				gwnSecond := net.IPNet{IP: gwIP, Mask: gwSubnet.Mask}

				var family, expNumAddrs int
				switch {
				case gwIP.To4() != nil:
					family = netlink.FAMILY_V4
					expNumAddrs = 1
				default:
					family = netlink.FAMILY_V6
					// Expect configured gw address plus link local
					expNumAddrs = 2
				}

				subnetsOverlap := gwnFirst.Contains(gwnSecond.IP) ||
					gwnSecond.Contains(gwnFirst.IP)

				err = originalNS.Do(func(ns.NetNS) error {
					defer GinkgoRecover()

					// Create the bridge
					bridge, _, err := setupBridge(conf)
					Expect(err).NotTo(HaveOccurred())

					// Function to check IP address(es) on bridge
					checkBridgeIPs := func(cidr0, cidr1 string) {
						addrs, err := netlink.AddrList(bridge, family)
						Expect(err).NotTo(HaveOccurred())
						Expect(addrs).To(HaveLen(expNumAddrs))
						addr := addrs[0].IPNet.String()
						Expect(addr).To(Equal(cidr0))
						if cidr1 != "" {
							addr = addrs[1].IPNet.String()
							Expect(addr).To(Equal(cidr1))
						}
					}

					// Check if ForceAddress has default value
					Expect(conf.ForceAddress).To(BeFalse())

					// Set first address on bridge
					err = ensureAddr(bridge, family, &gwnFirst, conf.ForceAddress)
					Expect(err).NotTo(HaveOccurred())
					checkBridgeIPs(tc.gwCIDRFirst, "")

					// Attempt to set the second address on the bridge
					// with ForceAddress set to false.
					err = ensureAddr(bridge, family, &gwnSecond, false)
					if family == netlink.FAMILY_V4 || subnetsOverlap {
						// IPv4 or overlapping IPv6 subnets:
						// Expect an error, and address should remain the same
						Expect(err).To(HaveOccurred())
						checkBridgeIPs(tc.gwCIDRFirst, "")
					} else {
						// Non-overlapping IPv6 subnets:
						// There should be 2 addresses (in addition to link local)
						Expect(err).NotTo(HaveOccurred())
						expNumAddrs++
						checkBridgeIPs(tc.gwCIDRSecond, tc.gwCIDRFirst)
					}

					// Set the second address on the bridge
					// with ForceAddress set to true.
					err = ensureAddr(bridge, family, &gwnSecond, true)
					Expect(err).NotTo(HaveOccurred())
					if family == netlink.FAMILY_V4 || subnetsOverlap {
						// IPv4 or overlapping IPv6 subnets:
						// IP address should be reconfigured.
						checkBridgeIPs(tc.gwCIDRSecond, "")
					} else {
						// Non-overlapping IPv6 subnets:
						// There should be 2 addresses (in addition to link local)
						checkBridgeIPs(tc.gwCIDRSecond, tc.gwCIDRFirst)
					}

					return nil
				})
				Expect(err).NotTo(HaveOccurred())

				// Clean up bridge addresses for next test case
				delBridgeAddrs(originalNS)
			})
		}

		It(fmt.Sprintf("[%s] ensure promiscuous mode on bridge", ver), func() {
			const IFNAME = "bridge0"

			conf := &NetConf{
				NetConf: types.NetConf{
					Name: "testConfig",
					Type: "bridge",
				},
				BrName:      IFNAME,
				IsGW:        true,
				IPMasq:      false,
				HairpinMode: false,
				PromiscMode: true,
				MTU:         5000,
			}

			err := originalNS.Do(func(ns.NetNS) error {
				defer GinkgoRecover()

				conf.NetConf.CNIVersion = ver
				_, _, err := setupBridge(conf)
				Expect(err).NotTo(HaveOccurred())
				// Check if ForceAddress has default value
				Expect(conf.ForceAddress).To(BeFalse())

				// Check if promiscuous mode is set correctly
				link, err := netlink.LinkByName("bridge0")
				Expect(err).NotTo(HaveOccurred())

				Expect(link.Attrs().Promisc).To(Equal(1))
				return nil
			})
			Expect(err).NotTo(HaveOccurred())
		})

		for i, tc := range []testCase{
			{
				subnet: "10.1.2.0/24",
			},
			{
				subnet: "2001:db8:42::/64",
			},
		} {
			tc := tc
			i := i
			It(fmt.Sprintf("[%s] (%d) creates a bridge with a stable MAC addresses", ver, i), func() {
				err := originalNS.Do(func(ns.NetNS) error {
					defer GinkgoRecover()

					tc.cniVersion = ver
					_, _, err := setupBridge(tc.netConf())
					Expect(err).NotTo(HaveOccurred())
					link, err := netlink.LinkByName(BRNAME)
					Expect(err).NotTo(HaveOccurred())
					origMac := link.Attrs().HardwareAddr

					cmdAddDelTest(originalNS, targetNS, tc, dataDir)

					link, err = netlink.LinkByName(BRNAME)
					Expect(err).NotTo(HaveOccurred())
					Expect(link.Attrs().HardwareAddr).To(Equal(origMac))
					return nil
				})
				Expect(err).NotTo(HaveOccurred())
			})
		}

		It(fmt.Sprintf("[%s] uses an explicit MAC addresses for the container iface (from CNI_ARGS)", ver), func() {
			err := originalNS.Do(func(ns.NetNS) error {
				defer GinkgoRecover()

				const expectedMac = "02:00:00:00:00:00"
				tc := testCase{
					cniVersion: ver,
					subnet:     "10.1.2.0/24",
					envArgs:    "MAC=" + expectedMac,

					expectedMac: expectedMac,
				}
				cmdAddDelTest(originalNS, targetNS, tc, dataDir)

				return nil
			})
			Expect(err).NotTo(HaveOccurred())
		})

		It(fmt.Sprintf("[%s] uses an explicit MAC addresses for the container iface (from Args)", ver), func() {
			err := originalNS.Do(func(ns.NetNS) error {
				defer GinkgoRecover()

				const expectedMac = "02:00:00:00:00:00"
				tc := testCase{
					cniVersion: ver,
					subnet:     "10.1.2.0/24",
					envArgs:    "MAC=" + "02:00:00:00:04:56",

					expectedMac: expectedMac,
				}
				tc.args.cni.mac = expectedMac
				cmdAddDelTest(originalNS, targetNS, tc, dataDir)

				return nil
			})
			Expect(err).NotTo(HaveOccurred())
		})

		It(fmt.Sprintf("[%s] uses an explicit MAC addresses for the container iface (from RuntimeConfig)", ver), func() {
			err := originalNS.Do(func(ns.NetNS) error {
				defer GinkgoRecover()

				const expectedMac = "02:00:00:00:00:00"
				tc := testCase{
					cniVersion: ver,
					subnet:     "10.1.2.0/24",
					envArgs:    "MAC=" + "02:00:00:00:04:56",

					expectedMac: expectedMac,
				}
				tc.args.cni.mac = "02:00:00:00:07:89"
				tc.runtimeConfig.mac = expectedMac
				cmdAddDelTest(originalNS, targetNS, tc, dataDir)

				return nil
			})
			Expect(err).NotTo(HaveOccurred())
		})

		It(fmt.Sprintf("[%s] checks ip release in case of error", ver), func() {
			err := originalNS.Do(func(ns.NetNS) error {
				defer GinkgoRecover()
				tc := testCase{
					cniVersion: ver,
					subnet:     "10.1.2.0/24",
				}

				_, _, err := setupBridge(tc.netConf())
				Expect(err).NotTo(HaveOccurred())

				args := tc.createCmdArgs(originalNS, dataDir)

				// get number of allocated IPs before asking for a new one
				before, err := countIPAMIPs(dataDir)
				Expect(err).NotTo(HaveOccurred())

				debugPostIPAMError = fmt.Errorf("debugPostIPAMError")
				_, _, err = testutils.CmdAddWithArgs(args, func() error {
					return cmdAdd(args)
				})
				Expect(err).To(MatchError("debugPostIPAMError"))

				// get number of allocated IPs after failure
				after, err := countIPAMIPs(dataDir)
				Expect(err).NotTo(HaveOccurred())

				Expect(before).To(Equal(after))
				return nil
			})
			Expect(err).NotTo(HaveOccurred())
		})

		if testutils.SpecVersionHasChaining(ver) {
			for _, tc := range []testCase{
				{
					ranges: []rangeInfo{{
						subnet: "10.1.2.0/24",
					}},
					ipMasq:     true,
					cniVersion: ver,
				},
				{
					ranges: []rangeInfo{{
						subnet: "10.1.2.0/24",
					}},
					ipMasq:        true,
					ipMasqBackend: "iptables",
					cniVersion:    ver,
				},
				{
					ranges: []rangeInfo{{
						subnet: "10.1.2.0/24",
					}},
					ipMasq:        true,
					ipMasqBackend: "nftables",
					cniVersion:    ver,
				},
			} {
				tc := tc
				It(fmt.Sprintf("[%s] configures a bridge and ipMasq rules with ipMasqBackend %q", ver, tc.ipMasqBackend), func() {
					err := originalNS.Do(func(ns.NetNS) error {
						defer GinkgoRecover()

						args := tc.createCmdArgs(originalNS, dataDir)
						r, _, err := testutils.CmdAddWithArgs(args, func() error {
							return cmdAdd(args)
						})
						Expect(err).NotTo(HaveOccurred())
						result, err := types100.GetResult(r)
						Expect(err).NotTo(HaveOccurred())
						Expect(result.IPs).Should(HaveLen(1))

						ip := result.IPs[0].Address.IP.String()

						// Update this if the default ipmasq backend changes
						switch tc.ipMasqBackend {
						case "iptables", "":
							ipt, err := iptables.NewWithProtocol(iptables.ProtocolIPv4)
							Expect(err).NotTo(HaveOccurred())

							rules, err := ipt.List("nat", "POSTROUTING")
							Expect(err).NotTo(HaveOccurred())
							Expect(rules).Should(ContainElement(ContainSubstring(ip)))
						case "nftables":
							nft, err := knftables.New(knftables.InetFamily, "cni_plugins_masquerade")
							Expect(err).NotTo(HaveOccurred())
							rules, err := nft.ListRules(context.TODO(), "masq_checks")
							Expect(err).NotTo(HaveOccurred())
							// FIXME: ListRules() doesn't return the actual rule strings,
							// and we can't easily compute the ipmasq plugin's comment.
							comments := 0
							for _, r := range rules {
								if r.Comment != nil {
									comments++
									break
								}
							}
							Expect(comments).To(Equal(1), "expected to find exactly one Rule with a comment")
						}

						err = testutils.CmdDelWithArgs(args, func() error {
							return cmdDel(args)
						})
						Expect(err).NotTo(HaveOccurred())
						return nil
					})
					Expect(err).NotTo(HaveOccurred())
				})
			}

			for i, tc := range []testCase{
				{
					// IPv4 only
					ranges: []rangeInfo{{
						subnet: "10.1.2.0/24",
					}},
					expGWCIDRs: []string{"10.1.2.1/24"},
				},
				{
					// IPv6 only
					ranges: []rangeInfo{{
						subnet: "2001:db8::0/64",
					}},
					expGWCIDRs: []string{"2001:db8::1/64"},
				},
				{
					// Dual-Stack
					ranges: []rangeInfo{
						{subnet: "192.168.0.0/24"},
						{subnet: "fd00::0/64"},
					},
					expGWCIDRs: []string{
						"192.168.0.1/24",
						"fd00::1/64",
					},
				},
			} {
				tc := tc
				i := i
				It(fmt.Sprintf("[%s] (%d) configures and deconfigures a bridge and veth with default route with ADD/DEL/CHECK", ver, i), func() {
					tc.cniVersion = ver
					cmdAddDelCheckTest(originalNS, targetNS, tc, dataDir)
				})
			}
		}

		It(fmt.Sprintf("[%s] configures mac spoof-check (no mac spoofing)", ver), func() {
			Expect(originalNS.Do(func(ns.NetNS) error {
				defer GinkgoRecover()

				tc := testCase{
					cniVersion:  ver,
					subnet:      "10.1.2.0/24",
					macspoofchk: true,
				}
				args := tc.createCmdArgs(originalNS, dataDir)
				_, _, err := testutils.CmdAddWithArgs(args, func() error {
					return cmdAdd(args)
				})
				Expect(err).NotTo(HaveOccurred())

				assertMacSpoofCheckRulesExist()

				Expect(testutils.CmdDelWithArgs(args, func() error {
					if err := cmdDel(args); err != nil {
						return err
					}
					assertMacSpoofCheckRulesMissing()
					return nil
				})).To(Succeed())

				return nil
			})).To(Succeed())
		})

		It(fmt.Sprintf("[%s] should fail when both IPAM and DisableContainerInterface are set", ver), func() {
			Expect(originalNS.Do(func(ns.NetNS) error {
				defer GinkgoRecover()
				tc := testCase{
					cniVersion:       ver,
					subnet:           "10.1.2.0/24",
					disableContIface: true,
				}
				args := tc.createCmdArgs(targetNS, dataDir)
				Expect(cmdAdd(args)).To(HaveOccurred())

				return nil
			})).To(Succeed())
		})

		It(fmt.Sprintf("[%s] should set the container veth peer state down", ver), func() {
			Expect(originalNS.Do(func(ns.NetNS) error {
				defer GinkgoRecover()
				tc := testCase{
					cniVersion:       ver,
					disableContIface: true,
					isLayer2:         true,
					AddErr020:        "cannot convert: no valid IP addresses",
					AddErr010:        "cannot convert: no valid IP addresses",
				}
				cmdAddDelTest(originalNS, targetNS, tc, dataDir)
				return nil
			})).To(Succeed())
		})
	}

	It("check vlan id when loading net conf", func() {
		type vlanTC struct {
			testCase
			err error
		}

		createCaseFn := func(ver string, vlan int, err error) vlanTC {
			return vlanTC{
				testCase: testCase{
					cniVersion: ver,
					vlan:       vlan,
				},
				err: err,
			}
		}

		tests := []vlanTC{}
		tests = append(tests, createCaseFn("1.0.0", 0, nil))
		tests = append(tests, createCaseFn("0.4.0", 0, nil))
		tests = append(tests, createCaseFn("1.0.0", -100, fmt.Errorf("invalid VLAN ID -100 (must be between 0 and 4094)")))
		tests = append(tests, createCaseFn("0.4.0", -100, fmt.Errorf("invalid VLAN ID -100 (must be between 0 and 4094)")))
		tests = append(tests, createCaseFn("1.0.0", 5000, fmt.Errorf("invalid VLAN ID 5000 (must be between 0 and 4094)")))
		tests = append(tests, createCaseFn("0.4.0", 5000, fmt.Errorf("invalid VLAN ID 5000 (must be between 0 and 4094)")))

		for _, test := range tests {
			_, _, err := loadNetConf([]byte(test.netConfJSON("")), "")
			if test.err == nil {
				Expect(err).ToNot(HaveOccurred())
			} else {
				Expect(err).To(Equal(test.err))
			}
		}
	})
})

func assertMacSpoofCheckRulesExist() {
	assertMacSpoofCheckRules(
		func(actual interface{}, expectedLen int) {
			ExpectWithOffset(3, actual).To(HaveLen(expectedLen))
		})
}

func assertMacSpoofCheckRulesMissing() {
	assertMacSpoofCheckRules(
		func(actual interface{}, _ int) {
			ExpectWithOffset(3, actual).To(BeEmpty())
		})
}

func assertMacSpoofCheckRules(assert func(actual interface{}, expectedLen int)) {
	c, err := nft.ReadConfig()
	ExpectWithOffset(2, err).NotTo(HaveOccurred())

	expectedTable := nft.NewTable("nat", "bridge")
	filter := nft.TypeFilter
	hook := nft.HookPreRouting
	prio := -300
	policy := nft.PolicyAccept
	expectedBaseChain := nft.NewChain(expectedTable, "PREROUTING", &filter, &hook, &prio, &policy)

	assert(c.LookupRule(nft.NewRule(
		expectedTable,
		expectedBaseChain,
		nil, nil, nil,
		"macspoofchk-dummy-0-eth0",
	)), 1)

	assert(c.LookupRule(nft.NewRule(
		expectedTable,
		nft.NewRegularChain(expectedTable, "cni-br-iface-dummy-0-eth0"),
		nil, nil, nil,
		"macspoofchk-dummy-0-eth0",
	)), 1)

	assert(c.LookupRule(nft.NewRule(
		expectedTable,
		nft.NewRegularChain(expectedTable, "cni-br-iface-dummy-0-eth0-mac"),
		nil, nil, nil,
		"macspoofchk-dummy-0-eth0",
	)), 2)
}
