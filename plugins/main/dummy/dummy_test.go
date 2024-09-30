// Copyright 2022 Arista Networks
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
	"errors"
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

const MASTER_NAME = "eth0"

type Net struct {
	Name          string                 `json:"name"`
	CNIVersion    string                 `json:"cniVersion"`
	Type          string                 `json:"type,omitempty"`
	IPAM          *allocator.IPAMConfig  `json:"ipam"`
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
	// verifyResult minimally verifies the Result and returns the interface's MAC address
	verifyResult(result types.Result, name string) string
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
func (t *testerV10x) verifyResult(result types.Result, name string) string {
	r, err := types100.GetResult(result)
	Expect(err).NotTo(HaveOccurred())

	Expect(r.Interfaces).To(HaveLen(1))
	Expect(r.Interfaces[0].Name).To(Equal(name))
	Expect(r.IPs).To(HaveLen(1))

	return r.Interfaces[0].Mac
}

func verify0403(result types.Result, name string) string {
	r, err := types040.GetResult(result)
	Expect(err).NotTo(HaveOccurred())

	Expect(r.Interfaces).To(HaveLen(1))
	Expect(r.Interfaces[0].Name).To(Equal(name))
	Expect(r.IPs).To(HaveLen(1))

	return r.Interfaces[0].Mac
}

// verifyResult minimally verifies the Result and returns the interface's MAC address
func (t *testerV04x) verifyResult(result types.Result, name string) string {
	return verify0403(result, name)
}

// verifyResult minimally verifies the Result and returns the interface's MAC address
func (t *testerV03x) verifyResult(result types.Result, name string) string {
	return verify0403(result, name)
}

// verifyResult minimally verifies the Result and returns the interface's MAC address
func (t *testerV01xOr02x) verifyResult(result types.Result, _ string) string {
	r, err := types020.GetResult(result)
	Expect(err).NotTo(HaveOccurred())

	Expect(r.IP4.IP.IP).NotTo(BeNil())
	Expect(r.IP6).To(BeNil())

	// 0.2 and earlier don't return MAC address
	return ""
}

var _ = Describe("dummy Operations", func() {
	var originalNS, targetNS ns.NetNS
	var dataDir string

	BeforeEach(func() {
		// Create a new NetNS so we don't modify the host
		var err error
		originalNS, err = testutils.NewNS()
		Expect(err).NotTo(HaveOccurred())
		targetNS, err = testutils.NewNS()
		Expect(err).NotTo(HaveOccurred())

		dataDir, err = os.MkdirTemp("", "dummy_test")
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
			m, err := netlink.LinkByName(MASTER_NAME)
			Expect(err).NotTo(HaveOccurred())
			err = netlink.LinkSetUp(m)
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

	for _, ver := range testutils.AllSpecVersions {
		// Redefine ver inside for scope so real value is picked up by each dynamically defined It()
		// See Gingkgo's "Patterns for dynamically generating tests" documentation.
		ver := ver

		It(fmt.Sprintf("[%s] creates an dummy link in a non-default namespace", ver), func() {
			// Create dummy in other namespace
			err := originalNS.Do(func(ns.NetNS) error {
				defer GinkgoRecover()

				_, err := createDummy("foobar0", targetNS)
				Expect(err).NotTo(HaveOccurred())
				return nil
			})
			Expect(err).NotTo(HaveOccurred())

			// Make sure dummy link exists in the target namespace
			err = targetNS.Do(func(ns.NetNS) error {
				defer GinkgoRecover()

				link, err := netlink.LinkByName("foobar0")
				Expect(err).NotTo(HaveOccurred())
				Expect(link.Attrs().Name).To(Equal("foobar0"))
				return nil
			})
			Expect(err).NotTo(HaveOccurred())
		})

		It(fmt.Sprintf("[%s] configures and deconfigures a dummy link with ADD/CHECK/DEL", ver), func() {
			const IFNAME = "dummy0"

			conf := fmt.Sprintf(`{
			    "cniVersion": "%s",
			    "name": "dummyTestv4",
			    "type": "dummy",
			    "ipam": {
					"type": "host-local",
					"subnet": "10.1.2.0/24",
					"dataDir": "%s"
			    }
			}`, ver, dataDir)

			args := &skel.CmdArgs{
				ContainerID: "contDummy",
				Netns:       targetNS.Path(),
				IfName:      IFNAME,
				StdinData:   []byte(conf),
			}

			t := newTesterByVersion(ver)

			var result types.Result
			var macAddress string
			err := originalNS.Do(func(ns.NetNS) error {
				defer GinkgoRecover()

				var err error
				if testutils.SpecVersionHasSTATUS(ver) {
					err = testutils.CmdStatus(func() error {
						return cmdStatus(args)
					})
					Expect(err).NotTo(HaveOccurred())
				}

				result, _, err = testutils.CmdAddWithArgs(args, func() error {
					return cmdAdd(args)
				})
				Expect(err).NotTo(HaveOccurred())

				macAddress = t.verifyResult(result, IFNAME)
				return nil
			})
			Expect(err).NotTo(HaveOccurred())
			// Make sure dummy link exists in the target namespace
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

			// call CmdCheck
			n := &Net{}
			err = json.Unmarshal([]byte(conf), &n)
			Expect(err).NotTo(HaveOccurred())

			n.IPAM, _, err = allocator.LoadIPAMConfig([]byte(conf), "")
			Expect(err).NotTo(HaveOccurred())

			newConf, err := buildOneConfig("dummyTestv4", ver, n, result)
			Expect(err).NotTo(HaveOccurred())

			confString, err := json.Marshal(newConf)
			Expect(err).NotTo(HaveOccurred())

			args.StdinData = confString
			// CNI Check dummy in the target namespace
			err = originalNS.Do(func(ns.NetNS) error {
				defer GinkgoRecover()
				return testutils.CmdCheckWithArgs(args, func() error { return cmdCheck(args) })
			})
			if testutils.SpecVersionHasCHECK(ver) {
				Expect(err).NotTo(HaveOccurred())
			} else {
				Expect(err).To(MatchError("config version does not allow CHECK"))
			}

			args.StdinData = []byte(conf)

			err = originalNS.Do(func(ns.NetNS) error {
				defer GinkgoRecover()

				err = testutils.CmdDelWithArgs(args, func() error {
					return cmdDel(args)
				})
				Expect(err).NotTo(HaveOccurred())
				return nil
			})
			Expect(err).NotTo(HaveOccurred())

			// Make sure dummy link has been deleted
			err = targetNS.Do(func(ns.NetNS) error {
				defer GinkgoRecover()

				link, err := netlink.LinkByName(IFNAME)
				Expect(err).To(HaveOccurred())
				Expect(link).To(BeNil())
				return nil
			})
			Expect(err).NotTo(HaveOccurred())

			// DEL can be called multiple times, make sure no error is returned
			// if the device is already removed.
			err = originalNS.Do(func(ns.NetNS) error {
				defer GinkgoRecover()

				err = testutils.CmdDelWithArgs(args, func() error {
					return cmdDel(args)
				})
				Expect(err).NotTo(HaveOccurred())
				return nil
			})
			Expect(err).NotTo(HaveOccurred())
		})

		It(fmt.Sprintf("[%s] fails to create dummy link with no ipam", ver), func() {
			var err error

			const confFmt = `{
			    "cniVersion": "%s",
			    "name": "mynet",
			    "type": "dummy"
			}`

			args := &skel.CmdArgs{
				ContainerID: "dummyCont",
				Netns:       "/var/run/netns/test",
				IfName:      "dummy0",
				StdinData:   []byte(fmt.Sprintf(confFmt, ver)),
			}

			_ = originalNS.Do(func(_ ns.NetNS) error {
				defer GinkgoRecover()

				_, _, err = testutils.CmdAddWithArgs(args, func() error {
					return cmdAdd(args)
				})
				Expect(err).To(Equal(errors.New("dummy interface requires an IPAM configuration")))
				return nil
			})
		})
	}
})
