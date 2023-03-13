// Copyright 2016 CNI authors
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
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Utils", func() {
	Describe("FormatChainName", func() {
		It("must format a short name", func() {
			chain := FormatChainName("test", "1234")
			Expect(chain).To(HaveLen(maxChainLength))
			Expect(chain).To(Equal("CNI-2bbe0c48b91a7d1b8a6753a8"))
		})

		It("must truncate a long name", func() {
			chain := FormatChainName("testalongnamethatdoesnotmakesense", "1234")
			Expect(chain).To(HaveLen(maxChainLength))
			Expect(chain).To(Equal("CNI-374f33fe84ab0ed84dcdebe3"))
		})

		It("must be predictable", func() {
			chain1 := FormatChainName("testalongnamethatdoesnotmakesense", "1234")
			chain2 := FormatChainName("testalongnamethatdoesnotmakesense", "1234")
			Expect(chain1).To(HaveLen(maxChainLength))
			Expect(chain2).To(HaveLen(maxChainLength))
			Expect(chain1).To(Equal(chain2))
		})

		It("must change when a character changes", func() {
			chain1 := FormatChainName("testalongnamethatdoesnotmakesense", "1234")
			chain2 := FormatChainName("testalongnamethatdoesnotmakesense", "1235")
			Expect(chain1).To(HaveLen(maxChainLength))
			Expect(chain2).To(HaveLen(maxChainLength))
			Expect(chain1).To(Equal("CNI-374f33fe84ab0ed84dcdebe3"))
			Expect(chain1).NotTo(Equal(chain2))
		})
	})

	Describe("MustFormatChainNameWithPrefix", func() {
		It("generates a chain name with a prefix", func() {
			chain := MustFormatChainNameWithPrefix("test", "1234", "PREFIX-")
			Expect(chain).To(HaveLen(maxChainLength))
			Expect(chain).To(Equal("CNI-PREFIX-2bbe0c48b91a7d1b8"))
		})

		It("must format a short name", func() {
			chain := MustFormatChainNameWithPrefix("test", "1234", "PREFIX-")
			Expect(chain).To(HaveLen(maxChainLength))
			Expect(chain).To(Equal("CNI-PREFIX-2bbe0c48b91a7d1b8"))
		})

		It("must truncate a long name", func() {
			chain := MustFormatChainNameWithPrefix("testalongnamethatdoesnotmakesense", "1234", "PREFIX-")
			Expect(chain).To(HaveLen(maxChainLength))
			Expect(chain).To(Equal("CNI-PREFIX-374f33fe84ab0ed84"))
		})

		It("must be predictable", func() {
			chain1 := MustFormatChainNameWithPrefix("testalongnamethatdoesnotmakesense", "1234", "PREFIX-")
			chain2 := MustFormatChainNameWithPrefix("testalongnamethatdoesnotmakesense", "1234", "PREFIX-")
			Expect(chain1).To(HaveLen(maxChainLength))
			Expect(chain2).To(HaveLen(maxChainLength))
			Expect(chain1).To(Equal(chain2))
		})

		It("must change when a character changes", func() {
			chain1 := MustFormatChainNameWithPrefix("testalongnamethatdoesnotmakesense", "1234", "PREFIX-")
			chain2 := MustFormatChainNameWithPrefix("testalongnamethatdoesnotmakesense", "1235", "PREFIX-")
			Expect(chain1).To(HaveLen(maxChainLength))
			Expect(chain2).To(HaveLen(maxChainLength))
			Expect(chain1).To(Equal("CNI-PREFIX-374f33fe84ab0ed84"))
			Expect(chain1).NotTo(Equal(chain2))
		})

		It("panics when prefix is too large", func() {
			longPrefix := strings.Repeat("PREFIX-", 4)
			Expect(func() {
				MustFormatChainNameWithPrefix("test", "1234", longPrefix)
			}).To(Panic())
		})
	})

	Describe("MustFormatHashWithPrefix", func() {
		It("always returns a string with the given prefix", func() {
			Expect(MustFormatHashWithPrefix(10, "AAA", "some string")).To(HavePrefix("AAA"))
			Expect(MustFormatHashWithPrefix(10, "foo", "some string")).To(HavePrefix("foo"))
			Expect(MustFormatHashWithPrefix(10, "bar", "some string")).To(HavePrefix("bar"))
		})

		It("always returns a string of the given length", func() {
			Expect(MustFormatHashWithPrefix(10, "AAA", "some string")).To(HaveLen(10))
			Expect(MustFormatHashWithPrefix(15, "AAA", "some string")).To(HaveLen(15))
			Expect(MustFormatHashWithPrefix(5, "AAA", "some string")).To(HaveLen(5))
		})

		It("is deterministic", func() {
			val1 := MustFormatHashWithPrefix(10, "AAA", "some string")
			val2 := MustFormatHashWithPrefix(10, "AAA", "some string")
			val3 := MustFormatHashWithPrefix(10, "AAA", "some string")
			Expect(val1).To(Equal(val2))
			Expect(val1).To(Equal(val3))
		})

		It("is (nearly) perfect (injective function)", func() {
			hashes := map[string]int{}

			for i := 0; i < 1000; i++ {
				name := fmt.Sprintf("string %d", i)
				hashes[MustFormatHashWithPrefix(8, "", name)]++
			}

			for key, count := range hashes {
				Expect(count).To(Equal(1), "for key "+key+" got non-unique correspondence")
			}
		})

		assertPanicWith := func(f func(), expectedErrorMessage string) {
			defer func() {
				Expect(recover()).To(Equal(expectedErrorMessage))
			}()
			f()
			Fail("function should have panicked but did not")
		}

		It("panics when prefix is longer than the length", func() {
			assertPanicWith(
				func() { MustFormatHashWithPrefix(3, "AAA", "some string") },
				"invalid length",
			)
		})

		It("panics when length is not positive", func() {
			assertPanicWith(
				func() { MustFormatHashWithPrefix(0, "", "some string") },
				"invalid length",
			)
		})

		It("panics when length is larger than MaxLen", func() {
			assertPanicWith(
				func() { MustFormatHashWithPrefix(MaxHashLen+1, "", "some string") },
				"invalid length",
			)
		})
	})
})
