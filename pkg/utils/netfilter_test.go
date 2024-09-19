// Copyright 2023 CNI authors
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
	"os"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("netfilter support", func() {
	When("it is available", func() {
		It("reports that iptables is supported", func() {
			Expect(SupportsIPTables()).To(BeTrue(), "This test should only fail if iptables is not available, but the test suite as a whole requires it to be available.")
		})
		It("reports that nftables is supported", func() {
			Expect(SupportsNFTables()).To(BeTrue(), "This test should only fail if nftables is not available, but the test suite as a whole requires it to be available.")
		})
	})

	// These are Serial because os.Setenv has process-wide effect
	When("it is not available", Serial, func() {
		var origPath string
		BeforeEach(func() {
			origPath = os.Getenv("PATH")
			os.Setenv("PATH", "/does-not-exist")
		})
		AfterEach(func() {
			os.Setenv("PATH", origPath)
		})

		It("reports that iptables is not supported", func() {
			Expect(SupportsIPTables()).To(BeFalse(), "found iptables outside of PATH??")
		})
		It("reports that nftables is not supported", func() {
			Expect(SupportsNFTables()).To(BeFalse(), "found nftables outside of PATH??")
		})
	})
})
