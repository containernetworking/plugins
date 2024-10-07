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
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"syscall"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/vishvananda/netlink"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	types020 "github.com/containernetworking/cni/pkg/types/020"
	types040 "github.com/containernetworking/cni/pkg/types/040"
	types100 "github.com/containernetworking/cni/pkg/types/100"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/containernetworking/plugins/pkg/testutils"
	"github.com/containernetworking/plugins/plugins/ipam/host-local/backend/allocator"
)

const (
	MASTER_NAME             = "eth0"
	MASTER_NAME_INCONTAINER = "eth1"
)

type Net struct {
	Name       string                `json:"name"`
	CNIVersion string                `json:"cniVersion"`
	Type       string                `json:"type,omitempty"`
	Master     string                `json:"master"`
	Mode       string                `json:"mode"`
	IPAM       *allocator.IPAMConfig `json:"ipam"`
	// RuntimeConfig struct {    // The capability arg
	//	IPRanges []RangeSet `json:"ipRanges,omitempty"`
	// Args *struct {
	// } `json:"runtimeConfig,omitempty"`
	//	A *IPAMArgs `json:"cni"`
	DNS           types.DNS              `json:"dns"`
	RawPrevResult map[string]interface{} `json:"prevResult,omitempty"`
	PrevResult    types100.Result        `json:"-"`
	LinkContNs    bool                   `json:"linkInContainer"`
}

func buildOneConfig(netName string, cniVersion string, orig *Net, prevResult types.Result) (*Net, error) {
	var err error

	inject := map[string]interface{}{
		"name":       netName,
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

type tester interface {
	// verifyResult minimally verifies the Result and returns the interface's MAC address
	verifyResult(result types.Result, err error, name string, numAddrs int) string
}

type testerBase struct{}

type (
	testerV10x      testerBase
	testerV04x      testerBase
	testerV03x      testerBase
	testerV01xOr02x testerBase
)

func newTesterByVersion(version string) tester {
	switch {
	case strings.HasPrefix(version, "1."):
		return &testerV10x{}
	case strings.HasPrefix(version, "0.4."):
		return &testerV04x{}
	case strings.HasPrefix(version, "0.3."):
		return &testerV03x{}
	default:
		return &testerV01xOr02x{}
	}
}

// verifyResult minimally verifies the Result and returns the interface's MAC address
func (t *testerV10x) verifyResult(result types.Result, err error, name string, numAddrs int) string {
	// Validate error from the CNI ADD
	Expect(err).NotTo(HaveOccurred())

	r, err := types100.GetResult(result)
	Expect(err).NotTo(HaveOccurred())

	Expect(r.Interfaces).To(HaveLen(1))
	Expect(r.Interfaces[0].Name).To(Equal(name))
	Expect(r.IPs).To(HaveLen(numAddrs))

	return r.Interfaces[0].Mac
}

func verify0403(result types.Result, err error, name string, numAddrs int) string {
	// Validate error from the CNI ADD
	Expect(err).NotTo(HaveOccurred())

	r, err := types040.GetResult(result)
	Expect(err).NotTo(HaveOccurred())

	Expect(r.Interfaces).To(HaveLen(1))
	Expect(r.Interfaces[0].Name).To(Equal(name))
	Expect(r.IPs).To(HaveLen(numAddrs))

	return r.Interfaces[0].Mac
}

// verifyResult minimally verifies the Result and returns the interface's MAC address
func (t *testerV04x) verifyResult(result types.Result, err error, name string, numAddrs int) string {
	return verify0403(result, err, name, numAddrs)
}

// verifyResult minimally verifies the Result and returns the interface's MAC address
func (t *testerV03x) verifyResult(result types.Result, err error, name string, numAddrs int) string {
	return verify0403(result, err, name, numAddrs)
}

// verifyResult minimally verifies the Result and returns the interface's MAC address
func (t *testerV01xOr02x) verifyResult(result types.Result, err error, _ string, numAddrs int) string {
	if result == nil && numAddrs == 0 {
		Expect(err).To(MatchError("cannot convert: no valid IP addresses"))
		return ""
	}

	r, err := types020.GetResult(result)
	Expect(err).NotTo(HaveOccurred())

	var numIPs int
	if r.IP4 != nil && r.IP4.IP.IP != nil {
		numIPs++
	}
	if r.IP6 != nil && r.IP6.IP.IP != nil {
		numIPs++
	}
	Expect(numIPs).To(Equal(numAddrs))

	// 0.2 and earlier don't return MAC address
	return ""
}

var _ = Describe("macvlan Operations", func() {
	var originalNS, targetNS ns.NetNS
	var dataDir string

	BeforeEach(func() {
		// Create a new NetNS so we don't modify the host
		var err error
		originalNS, err = testutils.NewNS()
		Expect(err).NotTo(HaveOccurred())
		targetNS, err = testutils.NewNS()
		Expect(err).NotTo(HaveOccurred())

		dataDir, err = os.MkdirTemp("", "macvlan_test")
		Expect(err).NotTo(HaveOccurred())

		err = originalNS.Do(func(ns.NetNS) error {
			defer GinkgoRecover()

			linkAttrs := netlink.NewLinkAttrs()
			linkAttrs.Name = MASTER_NAME
			// Add master
			err = netlink.LinkAdd(&netlink.Dummy{
				LinkAttrs: linkAttrs,
			})
			Expect(err).NotTo(HaveOccurred())
			_, err = netlink.LinkByName(MASTER_NAME)
			Expect(err).NotTo(HaveOccurred())
			return nil
		})
		Expect(err).NotTo(HaveOccurred())

		err = targetNS.Do(func(ns.NetNS) error {
			defer GinkgoRecover()

			linkAttrs := netlink.NewLinkAttrs()
			linkAttrs.Name = MASTER_NAME_INCONTAINER
			// Add master
			err = netlink.LinkAdd(&netlink.Dummy{
				LinkAttrs: linkAttrs,
			})
			Expect(err).NotTo(HaveOccurred())
			_, err = netlink.LinkByName(MASTER_NAME_INCONTAINER)
			Expect(err).NotTo(HaveOccurred())
			return nil
		})
		Expect(err).NotTo(HaveOccurred())
	})

	AfterEach(func() {
		Expect(os.RemoveAll(dataDir)).To(Succeed())
		Expect(originalNS.Close()).To(Succeed())
		Expect(testutils.UnmountNS(originalNS)).To(Succeed())
		Expect(targetNS.Close()).To(Succeed())
		Expect(testutils.UnmountNS(targetNS)).To(Succeed())
	})
	f, t := false, true
	for _, inContainer := range []*bool{&f, &t, nil} {
		isInContainer := inContainer
		masterInterface := MASTER_NAME
		if inContainer != nil && *inContainer {
			masterInterface = MASTER_NAME_INCONTAINER
		}
		linkInContainer := ""
		if isInContainer != nil {
			linkInContainer = fmt.Sprintf("\"linkInContainer\": %t,", *isInContainer)
		}
		for _, ver := range testutils.AllSpecVersions {
			// Redefine ver inside for scope so real value is picked up by each dynamically defined It()
			// See Gingkgo's "Patterns for dynamically generating tests" documentation.
			ver := ver

			It(fmt.Sprintf("[%s] creates an macvlan link in a non-default namespace", ver), func() {
				conf := &NetConf{
					NetConf: types.NetConf{
						CNIVersion: ver,
						Name:       "testConfig",
						Type:       "macvlan",
					},
					Master:     masterInterface,
					Mode:       "bridge",
					MTU:        1500,
					LinkContNs: isInContainer != nil && *isInContainer,
				}

				err := originalNS.Do(func(ns.NetNS) error {
					defer GinkgoRecover()

					_, err := createMacvlan(conf, "foobar0", targetNS)
					Expect(err).NotTo(HaveOccurred())
					return nil
				})
				Expect(err).NotTo(HaveOccurred())

				// Make sure macvlan link exists in the target namespace
				err = targetNS.Do(func(ns.NetNS) error {
					defer GinkgoRecover()

					link, err := netlink.LinkByName("foobar0")
					Expect(err).NotTo(HaveOccurred())
					Expect(link.Attrs().Name).To(Equal("foobar0"))
					return nil
				})
				Expect(err).NotTo(HaveOccurred())
			})

			It(fmt.Sprintf("[%s] configures and deconfigures a macvlan link with ADD/DEL", ver), func() {
				const IFNAME = "macvl0"

				conf := fmt.Sprintf(`{
			    "cniVersion": "%s",
			    "name": "mynet",
			    "type": "macvlan",
			    "master": "%s",
			    %s
			    "ipam": {
				"type": "host-local",
				"subnet": "10.1.2.0/24",
				"dataDir": "%s"
			    }
			}`, ver, masterInterface, linkInContainer, dataDir)

				args := &skel.CmdArgs{
					ContainerID: "dummy",
					Netns:       targetNS.Path(),
					IfName:      IFNAME,
					StdinData:   []byte(conf),
				}

				var macAddress string
				err := originalNS.Do(func(ns.NetNS) error {
					defer GinkgoRecover()

					if testutils.SpecVersionHasSTATUS(ver) {
						err := testutils.CmdStatus(func() error {
							return cmdStatus(args)
						})
						Expect(err).NotTo(HaveOccurred())
					}

					result, _, err := testutils.CmdAddWithArgs(args, func() error {
						return cmdAdd(args)
					})

					t := newTesterByVersion(ver)
					macAddress = t.verifyResult(result, err, IFNAME, 1)
					return nil
				})
				Expect(err).NotTo(HaveOccurred())

				// Make sure macvlan link exists in the target namespace
				err = targetNS.Do(func(ns.NetNS) error {
					defer GinkgoRecover()

					link, err := netlink.LinkByName(IFNAME)
					Expect(err).NotTo(HaveOccurred())
					Expect(link.Attrs().Name).To(Equal(IFNAME))

					if macAddress != "" {
						hwaddr, err := net.ParseMAC(macAddress)
						Expect(err).NotTo(HaveOccurred())
						Expect(link.Attrs().HardwareAddr).To(Equal(hwaddr))
					}

					addrs, err := netlink.AddrList(link, syscall.AF_INET)
					Expect(err).NotTo(HaveOccurred())
					Expect(addrs).To(HaveLen(1))
					return nil
				})
				Expect(err).NotTo(HaveOccurred())

				err = originalNS.Do(func(ns.NetNS) error {
					defer GinkgoRecover()

					err := testutils.CmdDelWithArgs(args, func() error {
						return cmdDel(args)
					})
					Expect(err).NotTo(HaveOccurred())
					return nil
				})
				Expect(err).NotTo(HaveOccurred())

				// Make sure macvlan link has been deleted
				err = targetNS.Do(func(ns.NetNS) error {
					defer GinkgoRecover()

					link, err := netlink.LinkByName(IFNAME)
					Expect(err).To(HaveOccurred())
					Expect(link).To(BeNil())
					return nil
				})
				Expect(err).NotTo(HaveOccurred())
			})

			It(fmt.Sprintf("[%s] deconfigures an unconfigured macvlan link with DEL", ver), func() {
				const IFNAME = "macvl0"

				conf := fmt.Sprintf(`{
			    "cniVersion": "%s",
			    "name": "mynet",
			    "type": "macvlan",
			    "master": "%s",
			    %s
			    "ipam": {
				"type": "host-local",
				"subnet": "10.1.2.0/24",
				"dataDir": "%s"
			    }
			}`, ver, masterInterface, linkInContainer, dataDir)

				args := &skel.CmdArgs{
					ContainerID: "dummy",
					Netns:       targetNS.Path(),
					IfName:      IFNAME,
					StdinData:   []byte(conf),
				}

				err := originalNS.Do(func(ns.NetNS) error {
					defer GinkgoRecover()

					err := testutils.CmdDelWithArgs(args, func() error {
						return cmdDel(args)
					})
					Expect(err).NotTo(HaveOccurred())
					return nil
				})
				Expect(err).NotTo(HaveOccurred())
			})

			It(fmt.Sprintf("[%s] configures and deconfigures a l2 macvlan link with ADD/DEL", ver), func() {
				const IFNAME = "macvl0"

				conf := fmt.Sprintf(`{
			    "cniVersion": "%s",
			    "name": "mynet",
			    "type": "macvlan",
			    "master": "%s",
			    %s
			    "ipam": {}
			}`, ver, masterInterface, linkInContainer)

				args := &skel.CmdArgs{
					ContainerID: "dummy",
					Netns:       targetNS.Path(),
					IfName:      IFNAME,
					StdinData:   []byte(conf),
				}

				var macAddress string
				err := originalNS.Do(func(ns.NetNS) error {
					defer GinkgoRecover()

					if testutils.SpecVersionHasSTATUS(ver) {
						err := testutils.CmdStatus(func() error {
							return cmdStatus(args)
						})
						Expect(err).NotTo(HaveOccurred())
					}

					result, _, err := testutils.CmdAddWithArgs(args, func() error {
						return cmdAdd(args)
					})

					t := newTesterByVersion(ver)
					macAddress = t.verifyResult(result, err, IFNAME, 0)
					return nil
				})
				Expect(err).NotTo(HaveOccurred())

				// Make sure macvlan link exists in the target namespace
				err = targetNS.Do(func(ns.NetNS) error {
					defer GinkgoRecover()

					link, err := netlink.LinkByName(IFNAME)
					Expect(err).NotTo(HaveOccurred())
					Expect(link.Attrs().Name).To(Equal(IFNAME))

					if macAddress != "" {
						hwaddr, err := net.ParseMAC(macAddress)
						Expect(err).NotTo(HaveOccurred())
						Expect(link.Attrs().HardwareAddr).To(Equal(hwaddr))
					}

					addrs, err := netlink.AddrList(link, syscall.AF_INET)
					Expect(err).NotTo(HaveOccurred())
					Expect(addrs).To(BeEmpty())
					return nil
				})
				Expect(err).NotTo(HaveOccurred())

				err = originalNS.Do(func(ns.NetNS) error {
					defer GinkgoRecover()

					err := testutils.CmdDelWithArgs(args, func() error {
						return cmdDel(args)
					})
					Expect(err).NotTo(HaveOccurred())
					return nil
				})
				Expect(err).NotTo(HaveOccurred())

				// Make sure macvlan link has been deleted
				err = targetNS.Do(func(ns.NetNS) error {
					defer GinkgoRecover()

					link, err := netlink.LinkByName(IFNAME)
					Expect(err).To(HaveOccurred())
					Expect(link).To(BeNil())
					return nil
				})
				Expect(err).NotTo(HaveOccurred())
			})

			It(fmt.Sprintf("[%s] configures and deconfigures a macvlan link with ADD/CHECK/DEL", ver), func() {
				const IFNAME = "macvl0"

				conf := fmt.Sprintf(`{
			    "cniVersion": "%s",
			    "name": "macvlanTestv4",
			    "type": "macvlan",
			    "master": "%s",
			    %s
			    "ipam": {
				"type": "host-local",
				"ranges": [[ {"subnet": "10.1.2.0/24", "gateway": "10.1.2.1"} ]],
				"dataDir": "%s"
			    }
			}`, ver, masterInterface, linkInContainer, dataDir)

				args := &skel.CmdArgs{
					ContainerID: "dummy",
					Netns:       targetNS.Path(),
					IfName:      IFNAME,
					StdinData:   []byte(conf),
				}

				var (
					macAddress string
					t          tester
					result     types.Result
				)
				err := originalNS.Do(func(ns.NetNS) error {
					defer GinkgoRecover()

					var err error
					if testutils.SpecVersionHasSTATUS(ver) {
						err := testutils.CmdStatus(func() error {
							return cmdStatus(args)
						})
						Expect(err).NotTo(HaveOccurred())
					}

					result, _, err = testutils.CmdAddWithArgs(args, func() error {
						return cmdAdd(args)
					})

					t = newTesterByVersion(ver)
					macAddress = t.verifyResult(result, err, IFNAME, 1)
					return nil
				})
				Expect(err).NotTo(HaveOccurred())

				// Make sure macvlan link exists in the target namespace
				err = targetNS.Do(func(ns.NetNS) error {
					defer GinkgoRecover()

					link, err := netlink.LinkByName(IFNAME)
					Expect(err).NotTo(HaveOccurred())
					Expect(link.Attrs().Name).To(Equal(IFNAME))

					if macAddress != "" {
						hwaddr, err := net.ParseMAC(macAddress)
						Expect(err).NotTo(HaveOccurred())
						Expect(link.Attrs().HardwareAddr).To(Equal(hwaddr))
					}

					addrs, err := netlink.AddrList(link, syscall.AF_INET)
					Expect(err).NotTo(HaveOccurred())
					Expect(addrs).To(HaveLen(1))
					return nil
				})
				Expect(err).NotTo(HaveOccurred())

				n := &Net{}
				err = json.Unmarshal([]byte(conf), &n)
				Expect(err).NotTo(HaveOccurred())

				n.IPAM, _, err = allocator.LoadIPAMConfig([]byte(conf), "")
				Expect(err).NotTo(HaveOccurred())

				newConf, err := buildOneConfig("macvlanTestv4", ver, n, result)
				Expect(err).NotTo(HaveOccurred())

				confString, err := json.Marshal(newConf)
				Expect(err).NotTo(HaveOccurred())

				args.StdinData = confString

				// CNI Check on macvlan in the target namespace
				err = originalNS.Do(func(ns.NetNS) error {
					defer GinkgoRecover()

					return testutils.CmdCheckWithArgs(args, func() error {
						return cmdCheck(args)
					})
				})
				if testutils.SpecVersionHasCHECK(ver) {
					Expect(err).NotTo(HaveOccurred())
				} else {
					Expect(err).To(MatchError("config version does not allow CHECK"))
				}

				err = originalNS.Do(func(ns.NetNS) error {
					defer GinkgoRecover()

					err := testutils.CmdDelWithArgs(args, func() error {
						return cmdDel(args)
					})
					Expect(err).NotTo(HaveOccurred())
					return nil
				})
				Expect(err).NotTo(HaveOccurred())

				// Make sure macvlan link has been deleted
				err = targetNS.Do(func(ns.NetNS) error {
					defer GinkgoRecover()

					link, err := netlink.LinkByName(IFNAME)
					Expect(err).To(HaveOccurred())
					Expect(link).To(BeNil())
					return nil
				})
				Expect(err).NotTo(HaveOccurred())
			})

			It(fmt.Sprintf("[%s] configures and deconfigures a macvlan link with ADD/DEL, without master config", ver), func() {
				const IFNAME = "macvl0"

				conf := fmt.Sprintf(`{
			    "cniVersion": "%s",
			    "name": "mynet",
			    "type": "macvlan",
			    %s
			    "ipam": {
				"type": "host-local",
				"subnet": "10.1.2.0/24",
				"dataDir": "%s"
			    }
			}`, ver, linkInContainer, dataDir)

				args := &skel.CmdArgs{
					ContainerID: "dummy",
					Netns:       targetNS.Path(),
					IfName:      IFNAME,
					StdinData:   []byte(conf),
				}
				currentNs := originalNS
				if isInContainer != nil && *isInContainer {
					currentNs = targetNS
				}

				// Make master as default route interface
				err := currentNs.Do(func(ns.NetNS) error {
					defer GinkgoRecover()

					link, err := netlink.LinkByName(masterInterface)
					Expect(err).NotTo(HaveOccurred())
					err = netlink.LinkSetUp(link)
					Expect(err).NotTo(HaveOccurred())

					address := &net.IPNet{IP: net.IPv4(192, 0, 0, 1), Mask: net.CIDRMask(24, 32)}
					addr := &netlink.Addr{IPNet: address}
					err = netlink.AddrAdd(link, addr)
					Expect(err).NotTo(HaveOccurred())

					// add default gateway into MASTER
					dst := &net.IPNet{
						IP:   net.IPv4(0, 0, 0, 0),
						Mask: net.CIDRMask(0, 0),
					}
					ip := net.IPv4(192, 0, 0, 254)
					route := netlink.Route{LinkIndex: link.Attrs().Index, Dst: dst, Gw: ip}
					err = netlink.RouteAdd(&route)
					Expect(err).NotTo(HaveOccurred())
					return nil
				})
				Expect(err).NotTo(HaveOccurred())

				var macAddress string
				err = originalNS.Do(func(ns.NetNS) error {
					defer GinkgoRecover()

					if testutils.SpecVersionHasSTATUS(ver) {
						err := testutils.CmdStatus(func() error {
							return cmdStatus(args)
						})
						Expect(err).NotTo(HaveOccurred())
					}

					result, _, err := testutils.CmdAddWithArgs(args, func() error {
						return cmdAdd(args)
					})

					t := newTesterByVersion(ver)
					macAddress = t.verifyResult(result, err, IFNAME, 1)
					return nil
				})
				Expect(err).NotTo(HaveOccurred())

				// Make sure macvlan link exists in the target namespace
				err = targetNS.Do(func(ns.NetNS) error {
					defer GinkgoRecover()

					link, err := netlink.LinkByName(IFNAME)
					Expect(err).NotTo(HaveOccurred())
					Expect(link.Attrs().Name).To(Equal(IFNAME))

					if macAddress != "" {
						hwaddr, err := net.ParseMAC(macAddress)
						Expect(err).NotTo(HaveOccurred())
						Expect(link.Attrs().HardwareAddr).To(Equal(hwaddr))
					}

					addrs, err := netlink.AddrList(link, syscall.AF_INET)
					Expect(err).NotTo(HaveOccurred())
					Expect(addrs).To(HaveLen(1))
					return nil
				})
				Expect(err).NotTo(HaveOccurred())

				err = originalNS.Do(func(ns.NetNS) error {
					defer GinkgoRecover()

					err := testutils.CmdDelWithArgs(args, func() error {
						return cmdDel(args)
					})
					Expect(err).NotTo(HaveOccurred())
					return nil
				})
				Expect(err).NotTo(HaveOccurred())

				// Make sure macvlan link has been deleted
				err = targetNS.Do(func(ns.NetNS) error {
					defer GinkgoRecover()

					link, err := netlink.LinkByName(IFNAME)
					Expect(err).To(HaveOccurred())
					Expect(link).To(BeNil())
					return nil
				})
				Expect(err).NotTo(HaveOccurred())
			})

			It(fmt.Sprintf("[%s] configures and deconfigures l2 macvlan link with mac address (from CNI_ARGS) with ADD/DEL", ver), func() {
				const (
					IFNAME       = "macvl0"
					EXPECTED_MAC = "c2:11:22:33:44:55"
				)

				conf := fmt.Sprintf(`{
			    "cniVersion": "%s",
			    "name": "mynet",
			    "type": "macvlan",
			    "master": "%s",
			    %s
			    "ipam": {}
			}`, ver, masterInterface, linkInContainer)

				args := &skel.CmdArgs{
					ContainerID: "dummy",
					Netns:       targetNS.Path(),
					IfName:      IFNAME,
					StdinData:   []byte(conf),
					Args:        fmt.Sprintf("IgnoreUnknown=true;MAC=%s", EXPECTED_MAC),
				}

				var macAddress string
				err := originalNS.Do(func(ns.NetNS) error {
					defer GinkgoRecover()

					result, _, err := testutils.CmdAddWithArgs(args, func() error {
						return cmdAdd(args)
					})

					t := newTesterByVersion(ver)
					macAddress = t.verifyResult(result, err, IFNAME, 0)
					if macAddress != "" {
						Expect(macAddress).To(Equal(EXPECTED_MAC))
					}
					return nil
				})
				Expect(err).NotTo(HaveOccurred())

				// Make sure macvlan link exists in the target namespace
				err = targetNS.Do(func(ns.NetNS) error {
					defer GinkgoRecover()

					link, err := netlink.LinkByName(IFNAME)
					Expect(err).NotTo(HaveOccurred())
					Expect(link.Attrs().Name).To(Equal(IFNAME))

					hwaddr, err := net.ParseMAC(EXPECTED_MAC)
					Expect(err).NotTo(HaveOccurred())
					Expect(link.Attrs().HardwareAddr).To(Equal(hwaddr))

					addrs, err := netlink.AddrList(link, syscall.AF_INET)
					Expect(err).NotTo(HaveOccurred())
					Expect(addrs).To(BeEmpty())
					return nil
				})
				Expect(err).NotTo(HaveOccurred())

				err = originalNS.Do(func(ns.NetNS) error {
					defer GinkgoRecover()

					err := testutils.CmdDelWithArgs(args, func() error {
						return cmdDel(args)
					})
					Expect(err).NotTo(HaveOccurred())
					return nil
				})
				Expect(err).NotTo(HaveOccurred())

				// Make sure macvlan link has been deleted
				err = targetNS.Do(func(ns.NetNS) error {
					defer GinkgoRecover()

					link, err := netlink.LinkByName(IFNAME)
					Expect(err).To(HaveOccurred())
					Expect(link).To(BeNil())
					return nil
				})
				Expect(err).NotTo(HaveOccurred())
			})

			It(fmt.Sprintf("[%s] configures and deconfigures l2 macvlan link with mac address (from RuntimeConfig) with ADD/DEL", ver), func() {
				const (
					IFNAME       = "macvl0"
					EXPECTED_MAC = "c2:11:22:33:44:55"
				)

				conf := fmt.Sprintf(`{
				"cniVersion": "%s",
				"capabilities": {"mac": true},
				"RuntimeConfig": {
					"mac": "c2:11:22:33:44:55"
				},
				"name": "mynet",
				"type": "macvlan",
				"master": "%s",
				%s
				"ipam": {}
			}`, ver, masterInterface, linkInContainer)

				args := &skel.CmdArgs{
					ContainerID: "dummy",
					Netns:       targetNS.Path(),
					IfName:      IFNAME,
					StdinData:   []byte(conf),
				}

				var macAddress string
				err := originalNS.Do(func(ns.NetNS) error {
					defer GinkgoRecover()

					result, _, err := testutils.CmdAddWithArgs(args, func() error {
						return cmdAdd(args)
					})

					t := newTesterByVersion(ver)
					macAddress = t.verifyResult(result, err, IFNAME, 0)
					if macAddress != "" {
						Expect(macAddress).To(Equal(EXPECTED_MAC))
					}
					return nil
				})
				Expect(err).NotTo(HaveOccurred())

				// Make sure macvlan link exists in the target namespace
				err = targetNS.Do(func(ns.NetNS) error {
					defer GinkgoRecover()

					link, err := netlink.LinkByName(IFNAME)
					Expect(err).NotTo(HaveOccurred())
					Expect(link.Attrs().Name).To(Equal(IFNAME))

					hwaddr, err := net.ParseMAC(EXPECTED_MAC)
					Expect(err).NotTo(HaveOccurred())
					Expect(link.Attrs().HardwareAddr).To(Equal(hwaddr))

					addrs, err := netlink.AddrList(link, syscall.AF_INET)
					Expect(err).NotTo(HaveOccurred())
					Expect(addrs).To(BeEmpty())
					return nil
				})
				Expect(err).NotTo(HaveOccurred())

				err = originalNS.Do(func(ns.NetNS) error {
					defer GinkgoRecover()

					err := testutils.CmdDelWithArgs(args, func() error {
						return cmdDel(args)
					})
					Expect(err).NotTo(HaveOccurred())
					return nil
				})
				Expect(err).NotTo(HaveOccurred())

				// Make sure macvlan link has been deleted
				err = targetNS.Do(func(ns.NetNS) error {
					defer GinkgoRecover()

					link, err := netlink.LinkByName(IFNAME)
					Expect(err).To(HaveOccurred())
					Expect(link).To(BeNil())
					return nil
				})
				Expect(err).NotTo(HaveOccurred())
			})
		}
	}
})
