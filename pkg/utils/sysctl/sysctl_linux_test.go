// Copyright 2017-2020 CNI authors
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

package sysctl_test

import (
	"fmt"
	"math/rand"
	"runtime"
	"strings"

	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/containernetworking/plugins/pkg/testutils"
	"github.com/containernetworking/plugins/pkg/utils/sysctl"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/vishvananda/netlink"
)

const (
	sysctlDotKeyTemplate   = "net.ipv4.conf.%s.proxy_arp"
	sysctlSlashKeyTemplate = "net/ipv4/conf/%s/proxy_arp"
)

var _ = Describe("Sysctl tests", func() {
	var testIfaceName string
	var cleanup func()

	BeforeEach(func() {

		// Save a reference to the original namespace,
		// Add a new NS
		currNs, err := ns.GetCurrentNS()
		Expect(err).NotTo(HaveOccurred())

		testNs, err := testutils.NewNS()
		Expect(err).NotTo(HaveOccurred())

		testIfaceName = fmt.Sprintf("cnitest.%d", rand.Intn(100000))
		testIface := &netlink.Dummy{
			LinkAttrs: netlink.LinkAttrs{
				Name:      testIfaceName,
				Namespace: netlink.NsFd(int(testNs.Fd())),
			},
		}

		err = netlink.LinkAdd(testIface)
		Expect(err).NotTo(HaveOccurred())

		runtime.LockOSThread()
		err = testNs.Set()
		Expect(err).NotTo(HaveOccurred())

		cleanup = func() {
			netlink.LinkDel(testIface)
			currNs.Set()
		}

	})

	AfterEach(func() {
		cleanup()
	})

	Describe("Sysctl", func() {
		It("reads keys with dot separators", func() {
			sysctlIfaceName := strings.Replace(testIfaceName, ".", "/", -1)
			sysctlKey := fmt.Sprintf(sysctlDotKeyTemplate, sysctlIfaceName)

			_, err := sysctl.Sysctl(sysctlKey)
			Expect(err).NotTo(HaveOccurred())
		})
	})

	Describe("Sysctl", func() {
		It("reads keys with slash separators", func() {
			sysctlKey := fmt.Sprintf(sysctlSlashKeyTemplate, testIfaceName)

			_, err := sysctl.Sysctl(sysctlKey)
			Expect(err).NotTo(HaveOccurred())
		})
	})

	Describe("Sysctl", func() {
		It("writes keys with dot separators", func() {
			sysctlIfaceName := strings.Replace(testIfaceName, ".", "/", -1)
			sysctlKey := fmt.Sprintf(sysctlDotKeyTemplate, sysctlIfaceName)

			_, err := sysctl.Sysctl(sysctlKey, "1")
			Expect(err).NotTo(HaveOccurred())
		})
	})

	Describe("Sysctl", func() {
		It("writes keys with slash separators", func() {
			sysctlKey := fmt.Sprintf(sysctlSlashKeyTemplate, testIfaceName)

			_, err := sysctl.Sysctl(sysctlKey, "1")
			Expect(err).NotTo(HaveOccurred())
		})
	})

})
