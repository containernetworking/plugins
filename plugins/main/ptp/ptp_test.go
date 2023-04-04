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
	"os"
	"strings"

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

type Net struct {
	Name          string                 `json:"name"`
	CNIVersion    string                 `json:"cniVersion"`
	Type          string                 `json:"type,omitempty"`
	IPMasq        bool                   `json:"ipMasq"`
	IPMasqBackend *string                `json:"ipMasqBackend,omitempty"`
	MTU           int                    `json:"mtu"`
	IPAM          *allocator.IPAMConfig  `json:"ipam"`
	DNS           types.DNS              `json:"dns"`
	RawPrevResult map[string]interface{} `json:"prevResult,omitempty"`
	PrevResult    types100.Result        `json:"-"`
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
	// verifyResult minimally verifies the Result and returns the interface's IP addresses and MAC address
	verifyResult(result types.Result, expectedIfName, expectedSandbox string, expectedDNS types.DNS) ([]resultIP, string)
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
	case strings.HasPrefix(version, "1.0."):
		return &testerV10x{}
	case strings.HasPrefix(version, "0.4."):
		return &testerV04x{}
	case strings.HasPrefix(version, "0.3."):
		return &testerV03x{}
	default:
		return &testerV01xOr02x{}
	}
}

type resultIP struct {
	ip string
	gw string
}

// verifyResult minimally verifies the Result and returns the interface's IP addresses and MAC address
func (t *testerV10x) verifyResult(result types.Result, expectedIfName, expectedSandbox string, expectedDNS types.DNS) ([]resultIP, string) {
	r, err := types100.GetResult(result)
	Expect(err).NotTo(HaveOccurred())

	Expect(r.Interfaces).To(HaveLen(2))
	Expect(r.Interfaces[0].Name).To(HavePrefix("veth"))
	Expect(r.Interfaces[0].Mac).To(HaveLen(17))
	Expect(r.Interfaces[0].Sandbox).To(BeEmpty())
	Expect(r.Interfaces[1].Name).To(Equal(expectedIfName))
	Expect(r.Interfaces[1].Sandbox).To(Equal(expectedSandbox))

	Expect(r.DNS).To(Equal(expectedDNS))

	// Grab IPs from container interface
	ips := []resultIP{}
	for _, ipc := range r.IPs {
		if *ipc.Interface == 1 {
			ips = append(ips, resultIP{
				ip: ipc.Address.IP.String(),
				gw: ipc.Gateway.String(),
			})
		}
	}

	return ips, r.Interfaces[1].Mac
}

func verify0403(result types.Result, expectedIfName, expectedSandbox string, expectedDNS types.DNS) ([]resultIP, string) {
	r, err := types040.GetResult(result)
	Expect(err).NotTo(HaveOccurred())

	Expect(r.Interfaces).To(HaveLen(2))
	Expect(r.Interfaces[0].Name).To(HavePrefix("veth"))
	Expect(r.Interfaces[0].Mac).To(HaveLen(17))
	Expect(r.Interfaces[0].Sandbox).To(BeEmpty())
	Expect(r.Interfaces[1].Name).To(Equal(expectedIfName))
	Expect(r.Interfaces[1].Sandbox).To(Equal(expectedSandbox))

	Expect(r.DNS).To(Equal(expectedDNS))

	// Grab IPs from container interface
	ips := []resultIP{}
	for _, ipc := range r.IPs {
		if *ipc.Interface == 1 {
			ips = append(ips, resultIP{
				ip: ipc.Address.IP.String(),
				gw: ipc.Gateway.String(),
			})
		}
	}

	return ips, r.Interfaces[1].Mac
}

// verifyResult minimally verifies the Result and returns the interface's IP addresses and MAC address
func (t *testerV04x) verifyResult(result types.Result, expectedIfName, expectedSandbox string, expectedDNS types.DNS) ([]resultIP, string) {
	return verify0403(result, expectedIfName, expectedSandbox, expectedDNS)
}

// verifyResult minimally verifies the Result and returns the interface's IP addresses and MAC address
func (t *testerV03x) verifyResult(result types.Result, expectedIfName, expectedSandbox string, expectedDNS types.DNS) ([]resultIP, string) {
	return verify0403(result, expectedIfName, expectedSandbox, expectedDNS)
}

// verifyResult minimally verifies the Result and returns the interface's IP addresses and MAC address
func (t *testerV01xOr02x) verifyResult(result types.Result, _, _ string, _ types.DNS) ([]resultIP, string) {
	r, err := types020.GetResult(result)
	Expect(err).NotTo(HaveOccurred())

	ips := []resultIP{}
	if r.IP4 != nil && r.IP4.IP.IP != nil {
		ips = append(ips, resultIP{
			ip: r.IP4.IP.IP.String(),
			gw: r.IP4.Gateway.String(),
		})
	}
	if r.IP6 != nil && r.IP6.IP.IP != nil {
		ips = append(ips, resultIP{
			ip: r.IP6.IP.IP.String(),
			gw: r.IP6.Gateway.String(),
		})
	}

	// 0.2 and earlier don't return MAC address
	return ips, ""
}

var _ = Describe("ptp Operations", func() {
	var originalNS, targetNS ns.NetNS
	var dataDir string

	BeforeEach(func() {
		// Create a new NetNS so we don't modify the host
		var err error
		originalNS, err = testutils.NewNS()
		Expect(err).NotTo(HaveOccurred())
		targetNS, err = testutils.NewNS()
		Expect(err).NotTo(HaveOccurred())

		dataDir, err = os.MkdirTemp("", "ptp_test")
		Expect(err).NotTo(HaveOccurred())
	})

	AfterEach(func() {
		Expect(os.RemoveAll(dataDir)).To(Succeed())
		Expect(originalNS.Close()).To(Succeed())
		Expect(testutils.UnmountNS(originalNS)).To(Succeed())
		Expect(targetNS.Close()).To(Succeed())
		Expect(testutils.UnmountNS(targetNS)).To(Succeed())
	})

	doTest := func(conf, cniVersion string, numIPs int, expectedDNSConf types.DNS, targetNS ns.NetNS) {
		const IFNAME = "ptp0"

		args := &skel.CmdArgs{
			ContainerID: "dummy",
			Netns:       targetNS.Path(),
			IfName:      IFNAME,
			StdinData:   []byte(conf),
		}

		var result types.Result

		// Execute the plugin with the ADD command, creating the veth endpoints
		err := originalNS.Do(func(ns.NetNS) error {
			defer GinkgoRecover()

			var err error
			result, _, err = testutils.CmdAddWithArgs(args, func() error {
				return cmdAdd(args)
			})
			Expect(err).NotTo(HaveOccurred())
			return nil
		})
		Expect(err).NotTo(HaveOccurred())

		t := newTesterByVersion(cniVersion)
		ips, mac := t.verifyResult(result, IFNAME, targetNS.Path(), expectedDNSConf)
		Expect(ips).To(HaveLen(numIPs))

		// Make sure ptp link exists in the target namespace
		// Then, ping the gateway
		err = targetNS.Do(func(ns.NetNS) error {
			defer GinkgoRecover()

			link, err := netlink.LinkByName(IFNAME)
			Expect(err).NotTo(HaveOccurred())
			if mac != "" {
				Expect(mac).To(Equal(link.Attrs().HardwareAddr.String()))
			}

			for _, ipc := range ips {
				fmt.Fprintln(GinkgoWriter, "ping", ipc.ip, "->", ipc.gw)
				if err := testutils.Ping(ipc.ip, ipc.gw, 30); err != nil {
					return fmt.Errorf("ping %s -> %s failed: %s", ipc.ip, ipc.gw, err)
				}
			}

			return nil
		})
		Expect(err).NotTo(HaveOccurred())

		// call CmdCheck
		n := &Net{}
		err = json.Unmarshal([]byte(conf), &n)
		Expect(err).NotTo(HaveOccurred())

		n.IPAM, _, err = allocator.LoadIPAMConfig([]byte(conf), "")
		Expect(err).NotTo(HaveOccurred())

		newConf, err := buildOneConfig(n.Name, cniVersion, n, result)
		Expect(err).NotTo(HaveOccurred())

		confString, err := json.Marshal(newConf)
		Expect(err).NotTo(HaveOccurred())

		args.StdinData = confString

		// CNI Check host-device in the target namespace
		err = originalNS.Do(func(ns.NetNS) error {
			defer GinkgoRecover()
			return testutils.CmdCheckWithArgs(args, func() error { return cmdCheck(args) })
		})
		if testutils.SpecVersionHasCHECK(cniVersion) {
			Expect(err).NotTo(HaveOccurred())
		} else {
			Expect(err).To(MatchError("config version does not allow CHECK"))
		}

		args.StdinData = []byte(conf)

		// Call the plugins with the DEL command, deleting the veth endpoints
		err = originalNS.Do(func(ns.NetNS) error {
			defer GinkgoRecover()

			err := testutils.CmdDelWithArgs(args, func() error {
				return cmdDel(args)
			})
			Expect(err).NotTo(HaveOccurred())
			return nil
		})
		Expect(err).NotTo(HaveOccurred())

		// Make sure ptp link has been deleted
		err = targetNS.Do(func(ns.NetNS) error {
			defer GinkgoRecover()

			link, err := netlink.LinkByName(IFNAME)
			Expect(err).To(HaveOccurred())
			Expect(link).To(BeNil())
			return nil
		})
		Expect(err).NotTo(HaveOccurred())
	}

	for _, ver := range testutils.AllSpecVersions {
		// Redefine ver inside for scope so real value is picked up by each dynamically defined It()
		// See Gingkgo's "Patterns for dynamically generating tests" documentation.
		ver := ver

		It(fmt.Sprintf("[%s] configures and deconfigures a ptp link with ADD/DEL", ver), func() {
			dnsConf := types.DNS{
				Nameservers: []string{"10.1.2.123"},
				Domain:      "some.domain.test",
				Search:      []string{"search.test"},
				Options:     []string{"option1:foo"},
			}
			dnsConfBytes, err := json.Marshal(dnsConf)
			Expect(err).NotTo(HaveOccurred())

			conf := fmt.Sprintf(`{
			    "cniVersion": "%s",
			    "name": "mynet",
			    "type": "ptp",
			    "ipMasq": true,
			    "mtu": 5000,
			    "ipam": {
				"type": "host-local",
				"subnet": "10.1.2.0/24",
				"dataDir": "%s"
			    },
			    "dns": %s
			}`, ver, dataDir, string(dnsConfBytes))

			doTest(conf, ver, 1, dnsConf, targetNS)
		})

		It(fmt.Sprintf("[%s] configures and deconfigures a ptp link when specifying ipMasqBackend: iptables", ver), func() {
			dnsConf := types.DNS{
				Nameservers: []string{"10.1.2.123"},
				Domain:      "some.domain.test",
				Search:      []string{"search.test"},
				Options:     []string{"option1:foo"},
			}
			dnsConfBytes, err := json.Marshal(dnsConf)
			Expect(err).NotTo(HaveOccurred())

			conf := fmt.Sprintf(`{
			    "cniVersion": "%s",
			    "name": "mynet",
			    "type": "ptp",
			    "ipMasq": true,
			    "ipMasqBackend": "iptables",
			    "mtu": 5000,
			    "ipam": {
				"type": "host-local",
				"subnet": "10.1.2.0/24",
				"dataDir": "%s"
			    },
			    "dns": %s
			}`, ver, dataDir, string(dnsConfBytes))

			doTest(conf, ver, 1, dnsConf, targetNS)
		})

		It(fmt.Sprintf("[%s] configures and deconfigures a ptp link when specifying ipMasqBackend: nftables", ver), func() {
			dnsConf := types.DNS{
				Nameservers: []string{"10.1.2.123"},
				Domain:      "some.domain.test",
				Search:      []string{"search.test"},
				Options:     []string{"option1:foo"},
			}
			dnsConfBytes, err := json.Marshal(dnsConf)
			Expect(err).NotTo(HaveOccurred())

			conf := fmt.Sprintf(`{
			    "cniVersion": "%s",
			    "name": "mynet",
			    "type": "ptp",
			    "ipMasq": true,
			    "ipMasqBackend": "nftables",
			    "mtu": 5000,
			    "ipam": {
				"type": "host-local",
				"subnet": "10.1.2.0/24",
				"dataDir": "%s"
			    },
			    "dns": %s
			}`, ver, dataDir, string(dnsConfBytes))

			doTest(conf, ver, 1, dnsConf, targetNS)
		})

		It(fmt.Sprintf("[%s] configures and deconfigures a dual-stack ptp link + routes with ADD/DEL", ver), func() {
			conf := fmt.Sprintf(`{
			    "cniVersion": "%s",
			    "name": "mynet",
			    "type": "ptp",
			    "ipMasq": true,
			    "mtu": 5000,
			    "ipam": {
				"type": "host-local",
				"ranges": [
					[{ "subnet": "10.1.2.0/24"}],
					[{ "subnet": "2001:db8:1::0/66"}]
				],
				"routes": [
				  { "dst": "0.0.0.0/0" },
				  { "dst": "192.168.0.0/16" },
				  { "dst": "1.2.3.4/32" }
				],
				"dataDir": "%s"
			    }
			}`, ver, dataDir)

			doTest(conf, ver, 2, types.DNS{}, targetNS)
		})

		It(fmt.Sprintf("[%s] does not override IPAM DNS settings if no DNS settings provided", ver), func() {
			ipamDNSConf := types.DNS{
				Nameservers: []string{"10.1.2.123"},
				Domain:      "some.domain.test",
				Search:      []string{"search.test"},
				Options:     []string{"option1:foo"},
			}
			resolvConfPath, err := testutils.TmpResolvConf(ipamDNSConf)
			Expect(err).NotTo(HaveOccurred())
			defer os.RemoveAll(resolvConfPath)

			conf := fmt.Sprintf(`{
			    "cniVersion": "%s",
			    "name": "mynet",
			    "type": "ptp",
			    "ipMasq": true,
			    "mtu": 5000,
			    "ipam": {
				"type": "host-local",
				"subnet": "10.1.2.0/24",
				"resolvConf": "%s",
				"dataDir": "%s"
			    }
			}`, ver, resolvConfPath, dataDir)

			doTest(conf, ver, 1, ipamDNSConf, targetNS)
		})

		It(fmt.Sprintf("[%s] overrides IPAM DNS settings if any DNS settings provided", ver), func() {
			ipamDNSConf := types.DNS{
				Nameservers: []string{"10.1.2.123"},
				Domain:      "some.domain.test",
				Search:      []string{"search.test"},
				Options:     []string{"option1:foo"},
			}
			resolvConfPath, err := testutils.TmpResolvConf(ipamDNSConf)
			Expect(err).NotTo(HaveOccurred())
			defer os.RemoveAll(resolvConfPath)

			for _, ptpDNSConf := range []types.DNS{
				{
					Nameservers: []string{"10.1.2.234"},
				},
				{
					Domain: "someother.domain.test",
				},
				{
					Search: []string{"search.elsewhere.test"},
				},
				{
					Options: []string{"option2:bar"},
				},
			} {
				dnsConfBytes, err := json.Marshal(ptpDNSConf)
				Expect(err).NotTo(HaveOccurred())

				conf := fmt.Sprintf(`{
				    "cniVersion": "%s",
				    "name": "mynet",
				    "type": "ptp",
				    "ipMasq": true,
				    "mtu": 5000,
				    "ipam": {
					"type": "host-local",
					"subnet": "10.1.2.0/24",
					"resolvConf": "%s",
					"dataDir": "%s"
				    },
				    "dns": %s
				}`, ver, resolvConfPath, dataDir, string(dnsConfBytes))

				doTest(conf, ver, 1, ptpDNSConf, targetNS)
			}
		})

		It(fmt.Sprintf("[%s] overrides IPAM DNS settings if any empty list DNS settings provided", ver), func() {
			ipamDNSConf := types.DNS{
				Nameservers: []string{"10.1.2.123"},
				Domain:      "some.domain.test",
				Search:      []string{"search.test"},
				Options:     []string{"option1:foo"},
			}
			resolvConfPath, err := testutils.TmpResolvConf(ipamDNSConf)
			Expect(err).NotTo(HaveOccurred())
			defer os.RemoveAll(resolvConfPath)

			conf := fmt.Sprintf(`{
			    "cniVersion": "%s",
			    "name": "mynet",
			    "type": "ptp",
			    "ipMasq": true,
			    "mtu": 5000,
			    "ipam": {
				"type": "host-local",
				"subnet": "10.1.2.0/24",
				"dataDir": "%s",
				"resolvConf": "%s"
			    },
			    "dns": {
				"nameservers": [],
				"search": [],
				"options": []
			    }
			}`, ver, dataDir, resolvConfPath)

			doTest(conf, ver, 1, types.DNS{}, targetNS)
		})

		It(fmt.Sprintf("[%s] deconfigures an unconfigured ptp link with DEL", ver), func() {
			const IFNAME = "ptp0"

			conf := fmt.Sprintf(`{
			    "cniVersion": "%s",
			    "name": "mynet",
			    "type": "ptp",
			    "ipMasq": true,
			    "mtu": 5000,
			    "ipam": {
				"type": "host-local",
				"dataDir": "%s",
				"subnet": "10.1.2.0/24"
			    }
			}`, ver, dataDir)

			args := &skel.CmdArgs{
				ContainerID: "dummy",
				Netns:       targetNS.Path(),
				IfName:      IFNAME,
				StdinData:   []byte(conf),
			}

			// Call the plugins with the DEL command. It should not error even though the veth doesn't exist.
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
	}
})
