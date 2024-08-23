// Copyright 2017-2018 CNI authors
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

package utils

import (
	"fmt"
	"math/rand"
	"runtime"

	"github.com/coreos/go-iptables/iptables"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/containernetworking/plugins/pkg/testutils"
)

const TABLE = "filter" // We'll monkey around here

var _ = Describe("chain tests", func() {
	var testChain string
	var ipt *iptables.IPTables
	var cleanup func()

	BeforeEach(func() {
		// Save a reference to the original namespace,
		// Add a new NS
		currNs, err := ns.GetCurrentNS()
		Expect(err).NotTo(HaveOccurred())

		testNs, err := testutils.NewNS()
		Expect(err).NotTo(HaveOccurred())

		testChain = fmt.Sprintf("cni-test-%d", rand.Intn(10000000))

		ipt, err = iptables.NewWithProtocol(iptables.ProtocolIPv4)
		Expect(err).NotTo(HaveOccurred())

		runtime.LockOSThread()
		err = testNs.Set()
		Expect(err).NotTo(HaveOccurred())

		cleanup = func() {
			if ipt == nil {
				return
			}
			ipt.ClearChain(TABLE, testChain)
			ipt.DeleteChain(TABLE, testChain)
			currNs.Set()
		}
	})

	AfterEach(func() {
		cleanup()
	})

	Describe("EnsureChain", func() {
		It("creates chains idempotently", func() {
			err := EnsureChain(ipt, TABLE, testChain)
			Expect(err).NotTo(HaveOccurred())

			// Create it again!
			err = EnsureChain(ipt, TABLE, testChain)
			Expect(err).NotTo(HaveOccurred())
		})
	})

	Describe("DeleteChain", func() {
		It("delete chains idempotently", func() {
			// Create chain
			err := EnsureChain(ipt, TABLE, testChain)
			Expect(err).NotTo(HaveOccurred())

			// Delete chain
			err = DeleteChain(ipt, TABLE, testChain)
			Expect(err).NotTo(HaveOccurred())

			// Delete it again!
			err = DeleteChain(ipt, TABLE, testChain)
			Expect(err).NotTo(HaveOccurred())
		})
	})
})
