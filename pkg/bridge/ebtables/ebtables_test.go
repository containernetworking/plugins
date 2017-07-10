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

package ebtables

import (
	utilexec "github.com/containernetworking/plugins/pkg/exec"
	"github.com/containernetworking/plugins/pkg/ns"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("EBTables Operations", func() {
	const (
		testChain   = "test"
		filterTable = "filter"
	)

	var (
		testNS ns.NetNS
		ebt    *EBTables
		err    error
	)

	BeforeEach(func() {
		ebt, err = New(utilexec.New())
		Expect(err).NotTo(HaveOccurred())
		testNS, err = ns.NewNS()
		Expect(err).NotTo(HaveOccurred())
		_ = testNS.Do(func(ns.NetNS) error {
			defer GinkgoRecover()
			err = ebt.NewChain(filterTable, testChain)
			Expect(err).NotTo(HaveOccurred())
			return nil
		})
	})

	AfterEach(func() {
		_ = testNS.Do(func(ns.NetNS) error {
			defer GinkgoRecover()
			Expect(testNS.Close()).To(Succeed())
			err = ebt.DeleteChain(filterTable, testChain)
			Expect(err).NotTo(HaveOccurred())
			return nil
		})
	})

	It("Appends a rule (IPv4)", func() {

		mac := "4e:4f:41:48:00:00"
		ip := "10.1.1.1"
		common_args := []string{"-p", "IPv4", "-s", mac, "-o", "veth+", "--ip-src"}

		_ = testNS.Do(func(ns.NetNS) error {
			defer GinkgoRecover()
			err = ebt.AppendUnique(filterTable, testChain, append(common_args, ip, "-j", "ACCEPT")...)
			Expect(err).NotTo(HaveOccurred())
			rules, err := ebt.List(filterTable, testChain)
			Expect(err).NotTo(HaveOccurred())
			Expect(len(rules)).To(Equal(1))
			return nil
		})
	})

	It("Appends a rule (IPv6)", func() {

		mac := "4e:4f:41:48:00:00"
		ip := "FD6D:8D64:AF0C::1"
		common_args := []string{"-p", "IPv6", "-s", mac, "-o", "veth+", "--ip6-src"}

		_ = testNS.Do(func(ns.NetNS) error {
			defer GinkgoRecover()
			err = ebt.AppendUnique(filterTable, testChain, append(common_args, ip, "-j", "ACCEPT")...)
			Expect(err).NotTo(HaveOccurred())
			rules, err := ebt.List(filterTable, testChain)
			Expect(err).NotTo(HaveOccurred())
			Expect(len(rules)).To(Equal(1))
			return nil
		})
	})

	It("Does not append an existing rule", func() {
		mac := "4e:4f:41:48:00:00"
		ip := "10.1.1.1"
		common_args := []string{"-p", "IPv4", "-s", mac, "-o", "veth+", "--ip-src"}
		_ = testNS.Do(func(ns.NetNS) error {
			defer GinkgoRecover()
			err = ebt.AppendUnique(filterTable, testChain, append(common_args, ip, "-j", "ACCEPT")...)
			Expect(err).NotTo(HaveOccurred())
			err = ebt.AppendUnique(filterTable, testChain, append(common_args, ip, "-j", "ACCEPT")...)
			Expect(err).NotTo(HaveOccurred())
			rules, err := ebt.List(filterTable, testChain)
			Expect(err).NotTo(HaveOccurred())
			Expect(len(rules)).To(Equal(1))
			return nil
		})
	})

	It("Inserts a rule.", func() {
		mac := "4e:4f:41:48:00:00"
		ip := "10.1.1.2"
		common_args := []string{"-p", "IPv4", "-s", mac, "-o", "veth+", "--ip-src"}

		_ = testNS.Do(func(ns.NetNS) error {
			defer GinkgoRecover()
			err = ebt.AppendUnique(filterTable, testChain, append(common_args, ip, "-j", "ACCEPT")...)
			Expect(err).NotTo(HaveOccurred())
			err = ebt.Insert(filterTable, testChain, 1, append(common_args, ip, "-j", "ACCEPT")...)
			Expect(err).NotTo(HaveOccurred())
			rules, err := ebt.List(filterTable, testChain)
			Expect(err).NotTo(HaveOccurred())
			// Make sure its the first rule.
			Expect(rules[0]).To(Equal("-p IPv4 -s 4e:4f:41:48:00:00 -o veth+ --ip-src 10.1.1.2 -j ACCEPT"))
			Expect(len(rules)).To(Equal(2))
			return nil
		})
	})

	It("Deletes a rule", func() {
		mac := "4e:4f:41:48:00:00"
		ip := "10.1.1.1"
		common_args := []string{"-p", "IPv4", "-s", mac, "-o", "veth+", "--ip-src"}

		_ = testNS.Do(func(ns.NetNS) error {
			defer GinkgoRecover()
			err = ebt.AppendUnique(filterTable, testChain, append(common_args, ip, "-j", "ACCEPT")...)
			Expect(err).NotTo(HaveOccurred())
			err = ebt.Delete(filterTable, testChain, append(common_args, ip, "-j", "ACCEPT")...)
			Expect(err).NotTo(HaveOccurred())
			rules, err := ebt.List(filterTable, testChain)
			Expect(err).NotTo(HaveOccurred())
			Expect(len(rules)).To(Equal(0))
			return nil
		})
	})
})
