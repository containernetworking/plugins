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
	Name          string                 `json:"name"`
	CNIVersion    string                 `json:"cniVersion"`
	Type          string                 `json:"type,omitempty"`
	Master        string                 `json:"master"`
	Mode          string                 `json:"mode"`
	IPAM          *allocator.IPAMConfig  `json:"ipam"`
	DNS           types.DNS              `json:"dns"`
	RawPrevResult map[string]interface{} `json:"prevResult,omitempty"`
	PrevResult    types100.Result        `json:"-"`
	LinkContNs    bool                   `json:"linkInContainer"`
}

func buildOneConfig(cniVersion string, master string, orig *Net, prevResult types.Result) (*Net, error) {
	confBytes, err := json.Marshal(orig)
	if err != nil {
		return nil, err
	}

	config := make(map[string]interface{})
	err = json.Unmarshal(confBytes, &config)
	if err != nil {
		return nil, fmt.Errorf("unmarshal existing network bytes: %s", err)
	}

	inject := map[string]interface{}{
		"name":       orig.Name,
		"cniVersion": orig.CNIVersion,
	}
	// Add previous plugin result
	if prevResult != nil && testutils.SpecVersionHasChaining(cniVersion) {
		inject["prevResult"] = prevResult
	}
	if master != "" {
		inject["master"] = master
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

func ipvlanAddCheckDelTest(conf, masterName string, originalNS, targetNS ns.NetNS) {
	// Unmarshal to pull out CNI spec version
	rawConfig := make(map[string]interface{})
	err := json.Unmarshal([]byte(conf), &rawConfig)
	Expect(err).NotTo(HaveOccurred())
	cniVersion := rawConfig["cniVersion"].(string)

	args := &skel.CmdArgs{
		ContainerID: "dummy",
		Netns:       targetNS.Path(),
		IfName:      "ipvl0",
		StdinData:   []byte(conf),
	}

	var result types.Result
	var macAddress string
	err = originalNS.Do(func(ns.NetNS) error {
		defer GinkgoRecover()

		if testutils.SpecVersionHasSTATUS(cniVersion) {
			err = testutils.CmdStatus(func() error {
				return cmdStatus(args)
			})
			Expect(err).NotTo(HaveOccurred())
		}

		result, _, err = testutils.CmdAddWithArgs(args, func() error {
			return cmdAdd(args)
		})
		Expect(err).NotTo(HaveOccurred())

		t := newTesterByVersion(cniVersion)
		macAddress = t.verifyResult(result, args.IfName)
		return nil
	})
	Expect(err).NotTo(HaveOccurred())

	// Make sure ipvlan link exists in the target namespace
	err = targetNS.Do(func(ns.NetNS) error {
		defer GinkgoRecover()

		link, err := netlink.LinkByName(args.IfName)
		Expect(err).NotTo(HaveOccurred())
		Expect(link.Attrs().Name).To(Equal(args.IfName))

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

	if n.IPAM != nil {
		n.IPAM, _, err = allocator.LoadIPAMConfig([]byte(conf), "")
		Expect(err).NotTo(HaveOccurred())
	}

	// build chained/cached config for DEL
	newConf, err := buildOneConfig(cniVersion, masterName, n, result)
	Expect(err).NotTo(HaveOccurred())
	confBytes, err := json.Marshal(newConf)
	Expect(err).NotTo(HaveOccurred())

	args.StdinData = confBytes
	GinkgoT().Logf(string(confBytes))

	if testutils.SpecVersionHasCHECK(cniVersion) {
		// CNI Check on ipvlan in the target namespace
		err = originalNS.Do(func(ns.NetNS) error {
			defer GinkgoRecover()

			return testutils.CmdCheckWithArgs(args, func() error {
				return cmdCheck(args)
			})
		})
		Expect(err).NotTo(HaveOccurred())
	}

	err = originalNS.Do(func(ns.NetNS) error {
		defer GinkgoRecover()

		err = testutils.CmdDelWithArgs(args, func() error {
			return cmdDel(args)
		})
		Expect(err).NotTo(HaveOccurred())
		return nil
	})
	Expect(err).NotTo(HaveOccurred())

	// Make sure ipvlan link has been deleted
	err = targetNS.Do(func(ns.NetNS) error {
		defer GinkgoRecover()

		link, err := netlink.LinkByName(args.IfName)
		Expect(err).To(HaveOccurred())
		Expect(link).To(BeNil())
		return nil
	})
	Expect(err).NotTo(HaveOccurred())
}

type tester interface {
	// verifyResult minimally verifies the Result and returns the interface's MAC address
	verifyResult(result types.Result, name string) string
}

type testerBase struct{}

type (
	testerV10x testerBase
	testerV04x testerBase
	testerV02x testerBase
)

func newTesterByVersion(version string) tester {
	switch {
	case strings.HasPrefix(version, "1."):
		return &testerV10x{}
	case strings.HasPrefix(version, "0.4.") || strings.HasPrefix(version, "0.3."):
		return &testerV04x{}
	case strings.HasPrefix(version, "0.1.") || strings.HasPrefix(version, "0.2."):
		return &testerV02x{}
	}
	Fail(fmt.Sprintf("unsupported config version %s", version))
	return nil
}

// verifyResult minimally verifies the Result and returns the interface's MAC address
func (t *testerV10x) verifyResult(result types.Result, name string) string {
	r, err := types100.GetResult(result)
	Expect(err).NotTo(HaveOccurred())

	Expect(r.Interfaces).To(HaveLen(1))
	Expect(r.Interfaces[0].Name).To(Equal(name))
	Expect(r.IPs).To(HaveLen(1))

	return r.Interfaces[0].Mac
}

// verifyResult minimally verifies the Result and returns the interface's MAC address
func (t *testerV04x) verifyResult(result types.Result, name string) string {
	r, err := types040.GetResult(result)
	Expect(err).NotTo(HaveOccurred())

	Expect(r.Interfaces).To(HaveLen(1))
	Expect(r.Interfaces[0].Name).To(Equal(name))
	Expect(r.IPs).To(HaveLen(1))

	return r.Interfaces[0].Mac
}

// verifyResult minimally verifies the Result and returns the interface's MAC address
func (t *testerV02x) verifyResult(result types.Result, _ string) string {
	r, err := types020.GetResult(result)
	Expect(err).NotTo(HaveOccurred())

	Expect(r.IP4.IP).NotTo(BeNil())
	Expect(r.IP4.IP.IP).NotTo(BeNil())
	Expect(r.IP6).To(BeNil())

	// 0.2 and earlier don't return MAC address
	return ""
}

var _ = Describe("ipvlan Operations", func() {
	var originalNS, targetNS ns.NetNS
	var dataDir string

	BeforeEach(func() {
		// Create a new NetNS so we don't modify the host
		var err error
		originalNS, err = testutils.NewNS()
		Expect(err).NotTo(HaveOccurred())

		targetNS, err = testutils.NewNS()
		Expect(err).NotTo(HaveOccurred())

		dataDir, err = os.MkdirTemp("", "ipvlan_test")
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

	for _, inContainer := range []bool{false, true} {
		masterInterface := MASTER_NAME
		if inContainer {
			masterInterface = MASTER_NAME_INCONTAINER
		}
		// for _, ver := range testutils.AllSpecVersions {
		for _, ver := range [...]string{"1.0.0"} {
			// Redefine ver inside for scope so real value is picked up by each dynamically defined It()
			// See Gingkgo's "Patterns for dynamically generating tests" documentation.
			ver := ver
			isInContainer := inContainer // Tests need a local var with constant value

			It(fmt.Sprintf("[%s] creates an ipvlan link in a non-default namespace", ver), func() {
				conf := &NetConf{
					NetConf: types.NetConf{
						CNIVersion: ver,
						Name:       "testConfig",
						Type:       "ipvlan",
					},
					Master:     masterInterface,
					Mode:       "l2",
					MTU:        1500,
					LinkContNs: isInContainer,
				}

				err := originalNS.Do(func(ns.NetNS) error {
					defer GinkgoRecover()

					_, err := createIpvlan(conf, "foobar0", targetNS)
					Expect(err).NotTo(HaveOccurred())
					return nil
				})

				Expect(err).NotTo(HaveOccurred())

				// Make sure ipvlan link exists in the target namespace
				err = targetNS.Do(func(ns.NetNS) error {
					defer GinkgoRecover()

					link, err := netlink.LinkByName("foobar0")
					Expect(err).NotTo(HaveOccurred())
					Expect(link.Attrs().Name).To(Equal("foobar0"))
					return nil
				})
				Expect(err).NotTo(HaveOccurred())
			})

			It(fmt.Sprintf("[%s] configures and deconfigures an iplvan link with ADD/DEL", ver), func() {
				conf := fmt.Sprintf(`{
			    "cniVersion": "%s",
			    "name": "mynet",
			    "type": "ipvlan",
			    "master": "%s",
				"linkInContainer": %t,
			    "ipam": {
				"type": "host-local",
				"subnet": "10.1.2.0/24",
				"dataDir": "%s"
			    }
			}`, ver, masterInterface, isInContainer, dataDir)

				ipvlanAddCheckDelTest(conf, "", originalNS, targetNS)
			})

			if testutils.SpecVersionHasChaining(ver) {
				It(fmt.Sprintf("[%s] configures and deconfigures an iplvan link with ADD/DEL when chained", ver), func() {
					conf := fmt.Sprintf(`{
				    "cniVersion": "%s",
				    "name": "mynet",
				    "type": "ipvlan",
					"linkInContainer": %t,
				    "prevResult": {
					    "interfaces": [
						    {
							    "name": "%s"
						    }
					    ],
					    "ips": [
						    {
							    "version": "4",
							    "address": "10.1.2.2/24",
							    "gateway": "10.1.2.1",
							    "interface": 0
						    }
					    ],
					    "routes": []
				    }
				}`, ver, isInContainer, masterInterface)

					ipvlanAddCheckDelTest(conf, masterInterface, originalNS, targetNS)
				})
			}

			It(fmt.Sprintf("[%s] deconfigures an unconfigured ipvlan link with DEL", ver), func() {
				conf := fmt.Sprintf(`{
			    "cniVersion": "%s",
			    "name": "mynet",
			    "type": "ipvlan",
			    "master": "%s",
				"linkInContainer": %t,
			    "ipam": {
				"type": "host-local",
				"subnet": "10.1.2.0/24",
				"dataDir": "%s"
			    }
			}`, ver, masterInterface, isInContainer, dataDir)

				args := &skel.CmdArgs{
					ContainerID: "dummy",
					Netns:       targetNS.Path(),
					IfName:      "ipvl0",
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

			It(fmt.Sprintf("[%s] configures and deconfigures a ipvlan link with ADD/DEL, without master config", ver), func() {
				conf := fmt.Sprintf(`{
			    "cniVersion": "%s",
			    "name": "mynet",
			    "type": "ipvlan",
				"linkInContainer": %t,
			    "ipam": {
				"type": "host-local",
				"subnet": "10.1.2.0/24",
				"dataDir": "%s"
			    }
			}`, ver, isInContainer, dataDir)

				// Make MASTER_NAME as default route interface
				currentNs := originalNS
				if isInContainer {
					currentNs = targetNS
				}
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

				ipvlanAddCheckDelTest(conf, masterInterface, originalNS, targetNS)
			})
		}
	}
})
