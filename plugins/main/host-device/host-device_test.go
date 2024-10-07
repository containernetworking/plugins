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
	"encoding/json"
	"fmt"
	"math/rand"
	"net"
	"os"
	"path"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/vishvananda/netlink"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	types040 "github.com/containernetworking/cni/pkg/types/040"
	types100 "github.com/containernetworking/cni/pkg/types/100"
	"github.com/containernetworking/cni/pkg/version"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/containernetworking/plugins/pkg/testutils"
)

type Net struct {
	Name          string                 `json:"name"`
	CNIVersion    string                 `json:"cniVersion"`
	Type          string                 `json:"type,omitempty"`
	Device        string                 `json:"device"`     // Device-Name, something like eth0 or can0 etc.
	HWAddr        string                 `json:"hwaddr"`     // MAC Address of target network interface
	KernelPath    string                 `json:"kernelpath"` // Kernelpath of the device
	PCIAddr       string                 `json:"pciBusID"`   // PCI Address of target network device
	IPAM          *IPAMConfig            `json:"ipam,omitempty"`
	DNS           types.DNS              `json:"dns"`
	RawPrevResult map[string]interface{} `json:"prevResult,omitempty"`
	PrevResult    types100.Result        `json:"-"`
}

type IPAMConfig struct {
	Name      string
	Type      string         `json:"type"`
	Routes    []*types.Route `json:"routes"`
	Addresses []Address      `json:"addresses,omitempty"`
	DNS       types.DNS      `json:"dns"`
}

type IPAMEnvArgs struct {
	types.CommonArgs
	IP      types.UnmarshallableString `json:"ip,omitempty"`
	GATEWAY types.UnmarshallableString `json:"gateway,omitempty"`
}

type Address struct {
	AddressStr string `json:"address"`
	Gateway    net.IP `json:"gateway,omitempty"`
	Address    net.IPNet
	Version    string
}

// canonicalizeIP makes sure a provided ip is in standard form
func canonicalizeIP(ip *net.IP) error {
	if ip.To4() != nil {
		*ip = ip.To4()
		return nil
	} else if ip.To16() != nil {
		*ip = ip.To16()
		return nil
	}
	return fmt.Errorf("IP %s not v4 nor v6", *ip)
}

// LoadIPAMConfig creates IPAMConfig using json encoded configuration provided
// as `bytes`. At the moment values provided in envArgs are ignored so there
// is no possibility to overload the json configuration using envArgs
func LoadIPAMConfig(bytes []byte, envArgs string) (*IPAMConfig, error) {
	n := Net{}
	if err := json.Unmarshal(bytes, &n); err != nil {
		return nil, err
	}

	if n.IPAM == nil {
		return nil, fmt.Errorf("IPAM config missing 'ipam' key")
	}

	// Validate all ranges
	numV4 := 0
	numV6 := 0

	for i := range n.IPAM.Addresses {
		ip, addr, err := net.ParseCIDR(n.IPAM.Addresses[i].AddressStr)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR %s: %s", n.IPAM.Addresses[i].AddressStr, err)
		}
		n.IPAM.Addresses[i].Address = *addr
		n.IPAM.Addresses[i].Address.IP = ip

		if err := canonicalizeIP(&n.IPAM.Addresses[i].Address.IP); err != nil {
			return nil, fmt.Errorf("invalid address %d: %s", i, err)
		}

		if n.IPAM.Addresses[i].Address.IP.To4() != nil {
			numV4++
		} else {
			numV6++
		}
	}

	if envArgs != "" {
		e := IPAMEnvArgs{}
		err := types.LoadArgs(envArgs, &e)
		if err != nil {
			return nil, err
		}

		if e.IP != "" {
			for _, item := range strings.Split(string(e.IP), ",") {
				ipstr := strings.TrimSpace(item)

				ip, subnet, err := net.ParseCIDR(ipstr)
				if err != nil {
					return nil, fmt.Errorf("invalid CIDR %s: %s", ipstr, err)
				}

				addr := Address{Address: net.IPNet{IP: ip, Mask: subnet.Mask}}
				if addr.Address.IP.To4() != nil {
					numV4++
				} else {
					numV6++
				}
				n.IPAM.Addresses = append(n.IPAM.Addresses, addr)
			}
		}

		if e.GATEWAY != "" {
			for _, item := range strings.Split(string(e.GATEWAY), ",") {
				gwip := net.ParseIP(strings.TrimSpace(item))
				if gwip == nil {
					return nil, fmt.Errorf("invalid gateway address: %s", item)
				}

				for i := range n.IPAM.Addresses {
					if n.IPAM.Addresses[i].Address.Contains(gwip) {
						n.IPAM.Addresses[i].Gateway = gwip
					}
				}
			}
		}
	}

	// CNI spec 0.2.0 and below supported only one v4 and v6 address
	if numV4 > 1 || numV6 > 1 {
		if ok, _ := version.GreaterThanOrEqualTo(n.CNIVersion, "0.3.0"); !ok {
			return nil, fmt.Errorf("CNI version %v does not support more than 1 address per family", n.CNIVersion)
		}
	}

	// Copy net name into IPAM so not to drag Net struct around
	n.IPAM.Name = n.Name

	return n.IPAM, nil
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

type tester interface {
	expectInterfaces(result types.Result, name, mac, sandbox string)
	expectDpdkInterfaceIP(result types.Result, ipAddress string)
}

type testerBase struct{}

type (
	testerV10x testerBase
	testerV04x testerBase
	testerV03x testerBase
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
		Fail(fmt.Sprintf("unsupported config version %s", version))
	}
	return nil
}

func (t *testerV10x) expectInterfaces(result types.Result, name, mac, sandbox string) {
	// check that the result was sane
	res, err := types100.NewResultFromResult(result)
	Expect(err).NotTo(HaveOccurred())
	Expect(res.Interfaces).To(Equal([]*types100.Interface{
		{
			Name:    name,
			Mac:     mac,
			Sandbox: sandbox,
		},
	}))
}

func (t *testerV10x) expectDpdkInterfaceIP(result types.Result, ipAddress string) {
	// check that the result was sane
	res, err := types100.NewResultFromResult(result)
	Expect(err).NotTo(HaveOccurred())
	Expect(res.Interfaces).To(BeEmpty())
	Expect(res.IPs).To(HaveLen(1))
	Expect(res.IPs[0].Address.String()).To(Equal(ipAddress))
}

func (t *testerV04x) expectInterfaces(result types.Result, name, mac, sandbox string) {
	// check that the result was sane
	res, err := types040.NewResultFromResult(result)
	Expect(err).NotTo(HaveOccurred())
	Expect(res.Interfaces).To(Equal([]*types040.Interface{
		{
			Name:    name,
			Mac:     mac,
			Sandbox: sandbox,
		},
	}))
}

func (t *testerV04x) expectDpdkInterfaceIP(result types.Result, ipAddress string) {
	// check that the result was sane
	res, err := types040.NewResultFromResult(result)
	Expect(err).NotTo(HaveOccurred())
	Expect(res.Interfaces).To(BeEmpty())
	Expect(res.IPs).To(HaveLen(1))
	Expect(res.IPs[0].Address.String()).To(Equal(ipAddress))
}

func (t *testerV03x) expectInterfaces(result types.Result, name, mac, sandbox string) {
	// check that the result was sane
	res, err := types040.NewResultFromResult(result)
	Expect(err).NotTo(HaveOccurred())
	Expect(res.Interfaces).To(Equal([]*types040.Interface{
		{
			Name:    name,
			Mac:     mac,
			Sandbox: sandbox,
		},
	}))
}

func (t *testerV03x) expectDpdkInterfaceIP(result types.Result, ipAddress string) {
	// check that the result was sane
	res, err := types040.NewResultFromResult(result)
	Expect(err).NotTo(HaveOccurred())
	Expect(res.Interfaces).To(BeEmpty())
	Expect(res.IPs).To(HaveLen(1))
	Expect(res.IPs[0].Address.String()).To(Equal(ipAddress))
}

var _ = Describe("base functionality", func() {
	var originalNS, targetNS ns.NetNS
	var ifname string

	BeforeEach(func() {
		var err error
		originalNS, err = testutils.NewNS()
		Expect(err).NotTo(HaveOccurred())
		targetNS, err = testutils.NewNS()
		Expect(err).NotTo(HaveOccurred())

		ifname = fmt.Sprintf("dummy-%x", rand.Int31())
	})

	AfterEach(func() {
		Expect(originalNS.Close()).To(Succeed())
		Expect(testutils.UnmountNS(originalNS)).To(Succeed())
		Expect(targetNS.Close()).To(Succeed())
		Expect(testutils.UnmountNS(targetNS)).To(Succeed())
	})

	for _, ver := range []string{"0.3.0", "0.3.1", "0.4.0", "1.0.0"} {
		// Redefine ver inside for scope so real value is picked up by each dynamically defined It()
		// See Gingkgo's "Patterns for dynamically generating tests" documentation.
		ver := ver

		It(fmt.Sprintf("[%s] works with a valid config without IPAM", ver), func() {
			var origLink netlink.Link

			// prepare ifname in original namespace
			_ = originalNS.Do(func(ns.NetNS) error {
				defer GinkgoRecover()
				linkAttrs := netlink.NewLinkAttrs()
				linkAttrs.Name = ifname
				err := netlink.LinkAdd(&netlink.Dummy{
					LinkAttrs: linkAttrs,
				})
				Expect(err).NotTo(HaveOccurred())
				origLink, err = netlink.LinkByName(ifname)
				Expect(err).NotTo(HaveOccurred())
				err = netlink.LinkSetUp(origLink)
				Expect(err).NotTo(HaveOccurred())
				return nil
			})

			// call CmdAdd
			cniName := "eth0"
			conf := fmt.Sprintf(`{
				"cniVersion": "%s",
				"name": "cni-plugin-host-device-test",
				"type": "host-device",
				"device": %q
			}`, ver, ifname)

			// if v1.1 or greater, call CmdStatus
			if testutils.SpecVersionHasSTATUS(ver) {
				err := testutils.CmdStatus(func() error {
					return cmdStatus(&skel.CmdArgs{StdinData: []byte(conf)})
				})
				Expect(err).NotTo(HaveOccurred())
			}

			args := &skel.CmdArgs{
				ContainerID: "dummy",
				Netns:       targetNS.Path(),
				IfName:      cniName,
				StdinData:   []byte(conf),
			}
			var resI types.Result
			err := originalNS.Do(func(ns.NetNS) error {
				defer GinkgoRecover()
				var err error
				resI, _, err = testutils.CmdAddWithArgs(args, func() error { return cmdAdd(args) })
				return err
			})
			Expect(err).NotTo(HaveOccurred())

			// check that the result was sane
			t := newTesterByVersion(ver)
			t.expectInterfaces(resI, cniName, origLink.Attrs().HardwareAddr.String(), targetNS.Path())

			// assert that dummy0 is now in the target namespace and is up
			_ = targetNS.Do(func(ns.NetNS) error {
				defer GinkgoRecover()
				link, err := netlink.LinkByName(cniName)
				Expect(err).NotTo(HaveOccurred())
				Expect(link.Attrs().HardwareAddr).To(Equal(origLink.Attrs().HardwareAddr))
				Expect(link.Attrs().Flags & net.FlagUp).To(Equal(net.FlagUp))
				return nil
			})

			// assert that dummy0 is now NOT in the original namespace anymore
			_ = originalNS.Do(func(ns.NetNS) error {
				defer GinkgoRecover()
				_, err := netlink.LinkByName(ifname)
				Expect(err).To(HaveOccurred())
				return nil
			})

			// Check that deleting the device moves it back and restores the name
			_ = originalNS.Do(func(ns.NetNS) error {
				defer GinkgoRecover()
				err := testutils.CmdDelWithArgs(args, func() error {
					return cmdDel(args)
				})
				Expect(err).NotTo(HaveOccurred())

				_, err = netlink.LinkByName(ifname)
				Expect(err).NotTo(HaveOccurred())
				return nil
			})
		})

		It(fmt.Sprintf("[%s] ensures CmdDel is idempotent", ver), func() {
			var (
				origLink     netlink.Link
				conflictLink netlink.Link
			)

			// prepare host device in original namespace
			_ = originalNS.Do(func(ns.NetNS) error {
				defer GinkgoRecover()
				linkAttrs := netlink.NewLinkAttrs()
				linkAttrs.Name = ifname
				err := netlink.LinkAdd(&netlink.Dummy{
					LinkAttrs: linkAttrs,
				})
				Expect(err).NotTo(HaveOccurred())
				origLink, err = netlink.LinkByName(ifname)
				Expect(err).NotTo(HaveOccurred())
				err = netlink.LinkSetUp(origLink)
				Expect(err).NotTo(HaveOccurred())
				return nil
			})

			// call CmdAdd
			cniName := "eth0"
			conf := fmt.Sprintf(`{
				"cniVersion": "%s",
				"name": "cni-plugin-host-device-test",
				"type": "host-device",
				"device": %q
			}`, ver, ifname)
			args := &skel.CmdArgs{
				ContainerID: "dummy",
				Netns:       targetNS.Path(),
				IfName:      cniName,
				StdinData:   []byte(conf),
			}
			var resI types.Result
			err := originalNS.Do(func(ns.NetNS) error {
				defer GinkgoRecover()
				var err error
				resI, _, err = testutils.CmdAddWithArgs(args, func() error { return cmdAdd(args) })
				return err
			})
			Expect(err).NotTo(HaveOccurred())

			// check that the result was sane
			t := newTesterByVersion(ver)
			t.expectInterfaces(resI, cniName, origLink.Attrs().HardwareAddr.String(), targetNS.Path())

			// assert that dummy0 is now in the target namespace and is up
			_ = targetNS.Do(func(ns.NetNS) error {
				defer GinkgoRecover()
				link, err := netlink.LinkByName(cniName)
				Expect(err).NotTo(HaveOccurred())
				Expect(link.Attrs().HardwareAddr).To(Equal(origLink.Attrs().HardwareAddr))
				Expect(link.Attrs().Flags & net.FlagUp).To(Equal(net.FlagUp))
				return nil
			})

			// assert that dummy0 is now NOT in the original namespace anymore
			_ = originalNS.Do(func(ns.NetNS) error {
				defer GinkgoRecover()
				_, err := netlink.LinkByName(ifname)
				Expect(err).To(HaveOccurred())
				return nil
			})

			// create another conflict host device with same name "dummy0"
			_ = originalNS.Do(func(ns.NetNS) error {
				defer GinkgoRecover()
				linkAttrs := netlink.NewLinkAttrs()
				linkAttrs.Name = ifname
				err := netlink.LinkAdd(&netlink.Dummy{
					LinkAttrs: linkAttrs,
				})
				Expect(err).NotTo(HaveOccurred())
				conflictLink, err = netlink.LinkByName(ifname)
				Expect(err).NotTo(HaveOccurred())
				err = netlink.LinkSetUp(conflictLink)
				Expect(err).NotTo(HaveOccurred())
				return nil
			})

			// try to call CmdDel and fails
			_ = originalNS.Do(func(ns.NetNS) error {
				defer GinkgoRecover()
				err = testutils.CmdDelWithArgs(args, func() error {
					return cmdDel(args)
				})
				Expect(err).To(HaveOccurred())
				return nil
			})

			// assert container interface "eth0" still exists in target namespace and is up
			_ = targetNS.Do(func(ns.NetNS) error {
				defer GinkgoRecover()
				link, err := netlink.LinkByName(cniName)
				Expect(err).NotTo(HaveOccurred())
				Expect(link.Attrs().HardwareAddr).To(Equal(origLink.Attrs().HardwareAddr))
				Expect(link.Attrs().Flags & net.FlagUp).To(Equal(net.FlagUp))
				return nil
			})

			// remove the conflict host device
			_ = originalNS.Do(func(ns.NetNS) error {
				defer GinkgoRecover()
				err = netlink.LinkDel(conflictLink)
				Expect(err).NotTo(HaveOccurred())
				return nil
			})

			// try to call CmdDel and succeed
			_ = originalNS.Do(func(ns.NetNS) error {
				defer GinkgoRecover()
				err = testutils.CmdDelWithArgs(args, func() error {
					return cmdDel(args)
				})
				Expect(err).NotTo(HaveOccurred())
				return nil
			})

			// assert that dummy0 is now back in the original namespace
			_ = originalNS.Do(func(ns.NetNS) error {
				defer GinkgoRecover()
				_, err := netlink.LinkByName(ifname)
				Expect(err).NotTo(HaveOccurred())
				return nil
			})
		})

		It(fmt.Sprintf("Works with a valid %s config on a DPDK device with IPAM", ver), func() {
			fs := &fakeFilesystem{
				dirs: []string{
					"sys/bus/pci/devices/0000:00:00.1",
					"sys/bus/pci/drivers/vfio-pci",
				},
				symlinks: map[string]string{
					"sys/bus/pci/devices/0000:00:00.1/driver": "../../../../bus/pci/drivers/vfio-pci",
				},
			}
			defer fs.use()()

			// call CmdAdd
			targetIP := "10.10.0.1/24"
			cniName := "eth0"
			conf := fmt.Sprintf(`{
							"cniVersion": "%s",
							"name": "cni-plugin-host-device-test",
							"type": "host-device",
							"ipam": {
								"type": "static",
								"addresses": [
									{
									"address":"`+targetIP+`",
									"gateway": "10.10.0.254"
								}]
							},
							"pciBusID": %q
						}`, ver, "0000:00:00.1")
			args := &skel.CmdArgs{
				ContainerID: "dummy",
				IfName:      cniName,
				Netns:       targetNS.Path(),
				StdinData:   []byte(conf),
			}
			var resI types.Result
			err := originalNS.Do(func(ns.NetNS) error {
				defer GinkgoRecover()
				var err error
				resI, _, err = testutils.CmdAddWithArgs(args, func() error { return cmdAdd(args) })
				return err
			})
			Expect(err).NotTo(HaveOccurred())

			// check that the result was sane
			t := newTesterByVersion(ver)
			t.expectDpdkInterfaceIP(resI, targetIP)

			// call CmdDel
			_ = originalNS.Do(func(ns.NetNS) error {
				defer GinkgoRecover()
				err = testutils.CmdDelWithArgs(args, func() error {
					return cmdDel(args)
				})
				Expect(err).NotTo(HaveOccurred())
				return nil
			})
		})

		It(fmt.Sprintf("Works with a valid %s config with IPAM", ver), func() {
			var origLink netlink.Link

			// prepare ifname in original namespace
			_ = originalNS.Do(func(ns.NetNS) error {
				defer GinkgoRecover()
				linkAttrs := netlink.NewLinkAttrs()
				linkAttrs.Name = ifname
				err := netlink.LinkAdd(&netlink.Dummy{
					LinkAttrs: linkAttrs,
				})
				Expect(err).NotTo(HaveOccurred())
				origLink, err = netlink.LinkByName(ifname)
				Expect(err).NotTo(HaveOccurred())
				err = netlink.LinkSetUp(origLink)
				Expect(err).NotTo(HaveOccurred())
				return nil
			})

			// call CmdAdd
			targetIP := "10.10.0.1/24"
			cniName := "eth0"
			conf := fmt.Sprintf(`{
				"cniVersion": "%s",
				"name": "cni-plugin-host-device-test",
				"type": "host-device",
				"ipam": {
					"type": "static",
					"addresses": [
						{
						"address":"`+targetIP+`",
						"gateway": "10.10.0.254"
					}]
				},
				"device": %q
			}`, ver, ifname)
			args := &skel.CmdArgs{
				ContainerID: "dummy",
				Netns:       targetNS.Path(),
				IfName:      cniName,
				StdinData:   []byte(conf),
			}
			var resI types.Result
			err := originalNS.Do(func(ns.NetNS) error {
				defer GinkgoRecover()
				var err error
				resI, _, err = testutils.CmdAddWithArgs(args, func() error { return cmdAdd(args) })
				return err
			})
			Expect(err).NotTo(HaveOccurred())

			// check that the result was sane
			t := newTesterByVersion(ver)
			t.expectInterfaces(resI, cniName, origLink.Attrs().HardwareAddr.String(), targetNS.Path())

			// assert that dummy0 is now in the target namespace and is up
			_ = targetNS.Do(func(ns.NetNS) error {
				defer GinkgoRecover()
				link, err := netlink.LinkByName(cniName)
				Expect(err).NotTo(HaveOccurred())
				Expect(link.Attrs().HardwareAddr).To(Equal(origLink.Attrs().HardwareAddr))
				Expect(link.Attrs().Flags & net.FlagUp).To(Equal(net.FlagUp))

				// get the IP address of the interface in the target namespace
				addrs, err := netlink.AddrList(link, netlink.FAMILY_V4)
				Expect(err).NotTo(HaveOccurred())
				addr := addrs[0].IPNet.String()
				// assert that IP address is what we set
				Expect(addr).To(Equal(targetIP))

				return nil
			})

			// assert that dummy0 is now NOT in the original namespace anymore
			_ = originalNS.Do(func(ns.NetNS) error {
				defer GinkgoRecover()
				_, err := netlink.LinkByName(ifname)
				Expect(err).To(HaveOccurred())
				return nil
			})

			// Check that deleting the device moves it back and restores the name
			_ = originalNS.Do(func(ns.NetNS) error {
				defer GinkgoRecover()
				err = testutils.CmdDelWithArgs(args, func() error {
					return cmdDel(args)
				})
				Expect(err).NotTo(HaveOccurred())

				_, err := netlink.LinkByName(ifname)
				Expect(err).NotTo(HaveOccurred())
				return nil
			})
		})

		It(fmt.Sprintf("[%s] fails an invalid config", ver), func() {
			conf := fmt.Sprintf(`{
				"cniVersion": "%s",
				"name": "cni-plugin-host-device-test",
				"type": "host-device"
			}`, ver)

			args := &skel.CmdArgs{
				ContainerID: "dummy",
				Netns:       originalNS.Path(),
				IfName:      ifname,
				StdinData:   []byte(conf),
			}
			_, _, err := testutils.CmdAddWithArgs(args, func() error { return cmdAdd(args) })
			Expect(err).To(MatchError(`specify either "device", "hwaddr", "kernelpath" or "pciBusID"`))
		})

		It(fmt.Sprintf("[%s] works with a valid config without IPAM", ver), func() {
			var origLink netlink.Link

			// prepare ifname in original namespace
			_ = originalNS.Do(func(ns.NetNS) error {
				defer GinkgoRecover()
				linkAttrs := netlink.NewLinkAttrs()
				linkAttrs.Name = ifname
				err := netlink.LinkAdd(&netlink.Dummy{
					LinkAttrs: linkAttrs,
				})
				Expect(err).NotTo(HaveOccurred())
				origLink, err = netlink.LinkByName(ifname)
				Expect(err).NotTo(HaveOccurred())
				err = netlink.LinkSetUp(origLink)
				Expect(err).NotTo(HaveOccurred())
				return nil
			})

			// call CmdAdd
			cniName := "eth0"
			conf := fmt.Sprintf(`{
				"cniVersion": "%s",
				"name": "cni-plugin-host-device-test",
				"type": "host-device",
				"device": %q
			}`, ver, ifname)
			args := &skel.CmdArgs{
				ContainerID: "dummy",
				Netns:       targetNS.Path(),
				IfName:      cniName,
				StdinData:   []byte(conf),
			}
			var resI types.Result
			err := originalNS.Do(func(ns.NetNS) error {
				defer GinkgoRecover()
				var err error
				resI, _, err = testutils.CmdAddWithArgs(args, func() error { return cmdAdd(args) })
				return err
			})
			Expect(err).NotTo(HaveOccurred())

			// check that the result was sane
			t := newTesterByVersion(ver)
			t.expectInterfaces(resI, cniName, origLink.Attrs().HardwareAddr.String(), targetNS.Path())

			// assert that dummy0 is now in the target namespace and is up
			_ = targetNS.Do(func(ns.NetNS) error {
				defer GinkgoRecover()
				link, err := netlink.LinkByName(cniName)
				Expect(err).NotTo(HaveOccurred())
				Expect(link.Attrs().HardwareAddr).To(Equal(origLink.Attrs().HardwareAddr))
				Expect(link.Attrs().Flags & net.FlagUp).To(Equal(net.FlagUp))
				return nil
			})

			// assert that dummy0 is now NOT in the original namespace anymore
			_ = originalNS.Do(func(ns.NetNS) error {
				defer GinkgoRecover()
				_, err := netlink.LinkByName(ifname)
				Expect(err).To(HaveOccurred())
				return nil
			})

			if testutils.SpecVersionHasCHECK(ver) {
				// call CmdCheck
				n := &Net{}
				err = json.Unmarshal([]byte(conf), &n)
				Expect(err).NotTo(HaveOccurred())

				newConf, err := buildOneConfig("testConfig", ver, n, resI)
				Expect(err).NotTo(HaveOccurred())

				confString, err := json.Marshal(newConf)
				Expect(err).NotTo(HaveOccurred())

				args.StdinData = confString

				// CNI Check host-device in the target namespace

				err = originalNS.Do(func(ns.NetNS) error {
					defer GinkgoRecover()
					return testutils.CmdCheckWithArgs(args, func() error { return cmdCheck(args) })
				})
				Expect(err).NotTo(HaveOccurred())
			}

			// Check that deleting the device moves it back and restores the name
			_ = originalNS.Do(func(ns.NetNS) error {
				defer GinkgoRecover()
				err = testutils.CmdDelWithArgs(args, func() error {
					return cmdDel(args)
				})
				Expect(err).NotTo(HaveOccurred())

				_, err := netlink.LinkByName(ifname)
				Expect(err).NotTo(HaveOccurred())
				return nil
			})
		})

		It(fmt.Sprintf("Works with a valid %s config on a DPDK device with IPAM", ver), func() {
			fs := &fakeFilesystem{
				dirs: []string{
					"sys/bus/pci/devices/0000:00:00.1",
					"sys/bus/pci/drivers/vfio-pci",
				},
				symlinks: map[string]string{
					"sys/bus/pci/devices/0000:00:00.1/driver": "../../../../bus/pci/drivers/vfio-pci",
				},
			}
			defer fs.use()()

			// call CmdAdd
			targetIP := "10.10.0.1/24"
			cniName := "eth0"
			conf := fmt.Sprintf(`{
							"cniVersion": "%s",
							"name": "cni-plugin-host-device-test",
							"type": "host-device",
							"ipam": {
								"type": "static",
								"addresses": [
									{
									"address":"`+targetIP+`",
									"gateway": "10.10.0.254"
								}]
							},
							"pciBusID": %q
						}`, ver, "0000:00:00.1")
			args := &skel.CmdArgs{
				ContainerID: "dummy",
				Netns:       targetNS.Path(),
				IfName:      cniName,
				StdinData:   []byte(conf),
			}
			var resI types.Result
			err := originalNS.Do(func(ns.NetNS) error {
				defer GinkgoRecover()
				var err error
				resI, _, err = testutils.CmdAddWithArgs(args, func() error { return cmdAdd(args) })
				return err
			})
			Expect(err).NotTo(HaveOccurred())

			// check that the result was sane
			t := newTesterByVersion(ver)
			t.expectDpdkInterfaceIP(resI, targetIP)

			// call CmdCheck
			n := &Net{}
			err = json.Unmarshal([]byte(conf), &n)
			Expect(err).NotTo(HaveOccurred())

			n.IPAM, err = LoadIPAMConfig([]byte(conf), "")
			Expect(err).NotTo(HaveOccurred())

			if testutils.SpecVersionHasCHECK(ver) {
				newConf, err := buildOneConfig("testConfig", ver, n, resI)
				Expect(err).NotTo(HaveOccurred())

				confString, err := json.Marshal(newConf)
				Expect(err).NotTo(HaveOccurred())

				args.StdinData = confString

				err = originalNS.Do(func(ns.NetNS) error {
					defer GinkgoRecover()
					return testutils.CmdCheckWithArgs(args, func() error { return cmdCheck(args) })
				})
				Expect(err).NotTo(HaveOccurred())
			}

			// call CmdDel
			_ = originalNS.Do(func(ns.NetNS) error {
				defer GinkgoRecover()
				err = testutils.CmdDelWithArgs(args, func() error {
					return cmdDel(args)
				})
				Expect(err).NotTo(HaveOccurred())
				return nil
			})
		})

		It(fmt.Sprintf("Works with a valid %s config on auxiliary device", ver), func() {
			var origLink netlink.Link
			ifname := "eth0"

			fs := &fakeFilesystem{
				dirs: []string{
					fmt.Sprintf("sys/bus/auxiliary/devices/mlx5_core.sf.4/net/%s", ifname),
				},
			}
			defer fs.use()()

			// prepare ifname in original namespace
			_ = originalNS.Do(func(ns.NetNS) error {
				defer GinkgoRecover()
				linkAttrs := netlink.NewLinkAttrs()
				linkAttrs.Name = ifname
				err := netlink.LinkAdd(&netlink.Dummy{
					LinkAttrs: linkAttrs,
				})
				Expect(err).NotTo(HaveOccurred())
				origLink, err = netlink.LinkByName(ifname)
				Expect(err).NotTo(HaveOccurred())
				err = netlink.LinkSetUp(origLink)
				Expect(err).NotTo(HaveOccurred())
				return nil
			})

			// call CmdAdd
			cniName := "net1"
			conf := fmt.Sprintf(`{
							"cniVersion": "%s",
							"name": "cni-plugin-host-device-test",
							"type": "host-device",
							"runtimeConfig": {"deviceID": %q}
						}`, ver, "mlx5_core.sf.4")
			args := &skel.CmdArgs{
				ContainerID: "dummy",
				IfName:      cniName,
				Netns:       targetNS.Path(),
				StdinData:   []byte(conf),
			}
			var resI types.Result
			err := originalNS.Do(func(ns.NetNS) error {
				defer GinkgoRecover()
				var err error
				resI, _, err = testutils.CmdAddWithArgs(args, func() error { return cmdAdd(args) })
				return err
			})
			Expect(err).NotTo(HaveOccurred())

			// check that the result was sane
			t := newTesterByVersion(ver)
			t.expectInterfaces(resI, cniName, origLink.Attrs().HardwareAddr.String(), targetNS.Path())

			// call CmdDel
			_ = originalNS.Do(func(ns.NetNS) error {
				defer GinkgoRecover()
				err = testutils.CmdDelWithArgs(args, func() error {
					return cmdDel(args)
				})
				Expect(err).NotTo(HaveOccurred())
				return nil
			})
		})

		It(fmt.Sprintf("Works with a valid %s config with IPAM", ver), func() {
			var origLink netlink.Link

			// prepare ifname in original namespace
			_ = originalNS.Do(func(ns.NetNS) error {
				defer GinkgoRecover()
				linkAttrs := netlink.NewLinkAttrs()
				linkAttrs.Name = ifname
				err := netlink.LinkAdd(&netlink.Dummy{
					LinkAttrs: linkAttrs,
				})
				Expect(err).NotTo(HaveOccurred())
				origLink, err = netlink.LinkByName(ifname)
				Expect(err).NotTo(HaveOccurred())
				err = netlink.LinkSetUp(origLink)
				Expect(err).NotTo(HaveOccurred())
				return nil
			})

			// call CmdAdd
			targetIP := "10.10.0.1/24"
			cniName := "eth0"
			conf := fmt.Sprintf(`{
				"cniVersion": "%s",
				"name": "cni-plugin-host-device-test",
				"type": "host-device",
				"ipam": {
					"type": "static",
					"addresses": [
						{
						"address":"`+targetIP+`",
						"gateway": "10.10.0.254"
					}]
				},
				"device": %q
			}`, ver, ifname)
			args := &skel.CmdArgs{
				ContainerID: "dummy",
				Netns:       targetNS.Path(),
				IfName:      cniName,
				StdinData:   []byte(conf),
			}
			var resI types.Result
			err := originalNS.Do(func(ns.NetNS) error {
				defer GinkgoRecover()
				var err error
				resI, _, err = testutils.CmdAddWithArgs(args, func() error { return cmdAdd(args) })
				return err
			})
			Expect(err).NotTo(HaveOccurred())

			// check that the result was sane
			t := newTesterByVersion(ver)
			t.expectInterfaces(resI, cniName, origLink.Attrs().HardwareAddr.String(), targetNS.Path())

			// assert that dummy0 is now in the target namespace and is up
			_ = targetNS.Do(func(ns.NetNS) error {
				defer GinkgoRecover()
				link, err := netlink.LinkByName(cniName)
				Expect(err).NotTo(HaveOccurred())
				Expect(link.Attrs().HardwareAddr).To(Equal(origLink.Attrs().HardwareAddr))
				Expect(link.Attrs().Flags & net.FlagUp).To(Equal(net.FlagUp))

				// get the IP address of the interface in the target namespace
				addrs, err := netlink.AddrList(link, netlink.FAMILY_V4)
				Expect(err).NotTo(HaveOccurred())
				addr := addrs[0].IPNet.String()
				// assert that IP address is what we set
				Expect(addr).To(Equal(targetIP))

				return nil
			})

			// assert that dummy0 is now NOT in the original namespace anymore
			_ = originalNS.Do(func(ns.NetNS) error {
				defer GinkgoRecover()
				_, err := netlink.LinkByName(ifname)
				Expect(err).To(HaveOccurred())
				return nil
			})

			// call CmdCheck
			n := &Net{}
			err = json.Unmarshal([]byte(conf), &n)
			Expect(err).NotTo(HaveOccurred())

			n.IPAM, err = LoadIPAMConfig([]byte(conf), "")
			Expect(err).NotTo(HaveOccurred())

			if testutils.SpecVersionHasCHECK(ver) {
				newConf, err := buildOneConfig("testConfig", ver, n, resI)
				Expect(err).NotTo(HaveOccurred())

				confString, err := json.Marshal(newConf)
				Expect(err).NotTo(HaveOccurred())

				args.StdinData = confString

				// CNI Check host-device in the target namespace

				err = originalNS.Do(func(ns.NetNS) error {
					defer GinkgoRecover()
					return testutils.CmdCheckWithArgs(args, func() error { return cmdCheck(args) })
				})
				Expect(err).NotTo(HaveOccurred())
			}

			// Check that deleting the device moves it back and restores the name
			_ = originalNS.Do(func(ns.NetNS) error {
				defer GinkgoRecover()
				err = testutils.CmdDelWithArgs(args, func() error {
					return cmdDel(args)
				})
				Expect(err).NotTo(HaveOccurred())

				_, err := netlink.LinkByName(ifname)
				Expect(err).NotTo(HaveOccurred())
				return nil
			})
		})

		It(fmt.Sprintf("Test idempotence of CmdDel with %s config", ver), func() {
			var (
				origLink     netlink.Link
				conflictLink netlink.Link
			)

			// prepare host device in original namespace
			_ = originalNS.Do(func(ns.NetNS) error {
				defer GinkgoRecover()
				linkAttrs := netlink.NewLinkAttrs()
				linkAttrs.Name = ifname
				err := netlink.LinkAdd(&netlink.Dummy{
					LinkAttrs: linkAttrs,
				})
				Expect(err).NotTo(HaveOccurred())
				origLink, err = netlink.LinkByName(ifname)
				Expect(err).NotTo(HaveOccurred())
				err = netlink.LinkSetUp(origLink)
				Expect(err).NotTo(HaveOccurred())
				return nil
			})

			// call CmdAdd
			cniName := "eth0"
			conf := fmt.Sprintf(`{
				"cniVersion": "%s",
				"name": "cni-plugin-host-device-test",
				"type": "host-device",
				"device": %q
			}`, ver, ifname)
			args := &skel.CmdArgs{
				ContainerID: "dummy",
				Netns:       targetNS.Path(),
				IfName:      cniName,
				StdinData:   []byte(conf),
			}
			var resI types.Result
			err := originalNS.Do(func(ns.NetNS) error {
				defer GinkgoRecover()
				var err error
				resI, _, err = testutils.CmdAddWithArgs(args, func() error { return cmdAdd(args) })
				return err
			})
			Expect(err).NotTo(HaveOccurred())

			// check that the result was sane
			t := newTesterByVersion(ver)
			t.expectInterfaces(resI, cniName, origLink.Attrs().HardwareAddr.String(), targetNS.Path())

			// assert that dummy0 is now in the target namespace and is up
			_ = targetNS.Do(func(ns.NetNS) error {
				defer GinkgoRecover()
				link, err := netlink.LinkByName(cniName)
				Expect(err).NotTo(HaveOccurred())
				Expect(link.Attrs().HardwareAddr).To(Equal(origLink.Attrs().HardwareAddr))
				Expect(link.Attrs().Flags & net.FlagUp).To(Equal(net.FlagUp))
				return nil
			})

			// assert that dummy0 is now NOT in the original namespace anymore
			_ = originalNS.Do(func(ns.NetNS) error {
				defer GinkgoRecover()
				_, err := netlink.LinkByName(ifname)
				Expect(err).To(HaveOccurred())
				return nil
			})

			// create another conflict host device with same name "dummy0"
			_ = originalNS.Do(func(ns.NetNS) error {
				defer GinkgoRecover()
				linkAttrs := netlink.NewLinkAttrs()
				linkAttrs.Name = ifname
				err := netlink.LinkAdd(&netlink.Dummy{
					LinkAttrs: linkAttrs,
				})
				Expect(err).NotTo(HaveOccurred())
				conflictLink, err = netlink.LinkByName(ifname)
				Expect(err).NotTo(HaveOccurred())
				err = netlink.LinkSetUp(conflictLink)
				Expect(err).NotTo(HaveOccurred())
				return nil
			})

			// try to call CmdDel and fails
			_ = originalNS.Do(func(ns.NetNS) error {
				defer GinkgoRecover()
				err = testutils.CmdDelWithArgs(args, func() error {
					return cmdDel(args)
				})
				Expect(err).To(HaveOccurred())
				return nil
			})

			// assert container interface "eth0" still exists in target namespace and is up
			err = targetNS.Do(func(ns.NetNS) error {
				defer GinkgoRecover()
				link, err := netlink.LinkByName(cniName)
				Expect(err).NotTo(HaveOccurred())
				Expect(link.Attrs().HardwareAddr).To(Equal(origLink.Attrs().HardwareAddr))
				Expect(link.Attrs().Flags & net.FlagUp).To(Equal(net.FlagUp))
				return nil
			})
			Expect(err).NotTo(HaveOccurred())

			// remove the conflict host device
			_ = originalNS.Do(func(ns.NetNS) error {
				defer GinkgoRecover()
				err = netlink.LinkDel(conflictLink)
				Expect(err).NotTo(HaveOccurred())
				return nil
			})

			// try to call CmdDel and succeed
			_ = originalNS.Do(func(ns.NetNS) error {
				defer GinkgoRecover()
				err = testutils.CmdDelWithArgs(args, func() error {
					return cmdDel(args)
				})
				Expect(err).NotTo(HaveOccurred())
				return nil
			})

			// assert that dummy0 is now back in the original namespace
			_ = originalNS.Do(func(ns.NetNS) error {
				defer GinkgoRecover()
				_, err := netlink.LinkByName(ifname)
				Expect(err).NotTo(HaveOccurred())
				return nil
			})
		})

		It(fmt.Sprintf("Test CmdAdd/Del when additioinal interface alreay exists in container ns with same name. %s config", ver), func() {
			var (
				origLink      netlink.Link
				containerLink netlink.Link
			)

			hostIfname := "eth0"
			containerAdditionalIfname := "eth0"

			// prepare host device in original namespace
			_ = originalNS.Do(func(ns.NetNS) error {
				defer GinkgoRecover()
				linkAttrs := netlink.NewLinkAttrs()
				linkAttrs.Name = hostIfname
				err := netlink.LinkAdd(&netlink.Dummy{
					LinkAttrs: linkAttrs,
				})
				Expect(err).NotTo(HaveOccurred())
				origLink, err = netlink.LinkByName(hostIfname)
				Expect(err).NotTo(HaveOccurred())
				err = netlink.LinkSetUp(origLink)
				Expect(err).NotTo(HaveOccurred())
				return nil
			})

			// prepare device in container namespace with same name as host device
			_ = targetNS.Do(func(ns.NetNS) error {
				defer GinkgoRecover()
				linkAttrs := netlink.NewLinkAttrs()
				linkAttrs.Name = containerAdditionalIfname
				err := netlink.LinkAdd(&netlink.Dummy{
					LinkAttrs: linkAttrs,
				})
				Expect(err).NotTo(HaveOccurred())
				containerLink, err = netlink.LinkByName(containerAdditionalIfname)
				Expect(err).NotTo(HaveOccurred())
				err = netlink.LinkSetUp(containerLink)
				Expect(err).NotTo(HaveOccurred())
				return nil
			})

			// call CmdAdd
			cniName := "net1"
			conf := fmt.Sprintf(`{
				"cniVersion": "%s",
				"name": "cni-plugin-host-device-test",
				"type": "host-device",
				"device": %q
			}`, ver, hostIfname)
			args := &skel.CmdArgs{
				ContainerID: "dummy",
				Netns:       targetNS.Path(),
				IfName:      cniName,
				StdinData:   []byte(conf),
			}
			var resI types.Result
			err := originalNS.Do(func(ns.NetNS) error {
				defer GinkgoRecover()
				var err error
				resI, _, err = testutils.CmdAddWithArgs(args, func() error { return cmdAdd(args) })
				return err
			})
			Expect(err).NotTo(HaveOccurred())

			// check that the result was sane
			t := newTesterByVersion(ver)
			t.expectInterfaces(resI, cniName, origLink.Attrs().HardwareAddr.String(), targetNS.Path())

			// assert that host device is now in the target namespace and is up
			_ = targetNS.Do(func(ns.NetNS) error {
				defer GinkgoRecover()
				link, err := netlink.LinkByName(cniName)
				Expect(err).NotTo(HaveOccurred())
				Expect(link.Attrs().HardwareAddr).To(Equal(origLink.Attrs().HardwareAddr))
				Expect(link.Attrs().Flags & net.FlagUp).To(Equal(net.FlagUp))
				return nil
			})

			// call CmdDel, expect it to succeed
			_ = originalNS.Do(func(ns.NetNS) error {
				defer GinkgoRecover()
				err = testutils.CmdDelWithArgs(args, func() error {
					return cmdDel(args)
				})
				Expect(err).ToNot(HaveOccurred())
				return nil
			})

			// assert container interface "eth0" still exists in target namespace and is up
			err = targetNS.Do(func(ns.NetNS) error {
				defer GinkgoRecover()
				link, err := netlink.LinkByName(containerAdditionalIfname)
				Expect(err).NotTo(HaveOccurred())
				Expect(link.Attrs().HardwareAddr).To(Equal(containerLink.Attrs().HardwareAddr))
				Expect(link.Attrs().Flags & net.FlagUp).To(Equal(net.FlagUp))
				return nil
			})
			Expect(err).NotTo(HaveOccurred())

			// assert that host device is now back in the original namespace
			_ = originalNS.Do(func(ns.NetNS) error {
				defer GinkgoRecover()
				_, err := netlink.LinkByName(hostIfname)
				Expect(err).NotTo(HaveOccurred())
				return nil
			})
		})
	}
})

type fakeFilesystem struct {
	rootDir  string
	dirs     []string
	symlinks map[string]string
}

func (fs *fakeFilesystem) use() func() {
	// create the new fake fs root dir in /tmp/sriov...
	tmpDir, err := os.MkdirTemp("", "sriov")
	if err != nil {
		panic(fmt.Errorf("error creating fake root dir: %s", err.Error()))
	}
	fs.rootDir = tmpDir

	for _, dir := range fs.dirs {
		err := os.MkdirAll(path.Join(fs.rootDir, dir), 0o755)
		if err != nil {
			panic(fmt.Errorf("error creating fake directory: %s", err.Error()))
		}
	}

	for link, target := range fs.symlinks {
		err = os.Symlink(target, path.Join(fs.rootDir, link))
		if err != nil {
			panic(fmt.Errorf("error creating fake symlink: %s", err.Error()))
		}
	}

	sysBusPCI = path.Join(fs.rootDir, "/sys/bus/pci/devices")
	sysBusAuxiliary = path.Join(fs.rootDir, "/sys/bus/auxiliary/devices")

	return func() {
		// remove temporary fake fs
		err := os.RemoveAll(fs.rootDir)
		if err != nil {
			panic(fmt.Errorf("error tearing down fake filesystem: %s", err.Error()))
		}
	}
}
