// Copyright 2018 CNI authors
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

package disk

import (
	"github.com/containernetworking/plugins/plugins/ipam/host-local/backend"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("ID parsing tests", func() {

	It("Parses a v0 key", func() {
		b := []byte("591df6e2-730c-11e8-84d4-507b9dee986d")
		key, kind, err := ReadKey(b)
		Expect(err).NotTo(HaveOccurred())

		Expect(kind).To(BeEquivalentTo(KindReservationV0))

		Expect(key).To(Equal(&backend.Key{ID: "591df6e2-730c-11e8-84d4-507b9dee986d"}))
	})

	It("Parses a v0 key that looks like json", func() {
		b := []byte(`{"a":"b"}`)
		key, kind, err := ReadKey(b)
		Expect(err).NotTo(HaveOccurred())

		Expect(kind).To(BeEquivalentTo(KindReservationV0))

		Expect(key).To(Equal(&backend.Key{ID: `{"a":"b"}`}))

	})

	It("Parses a v1 key", func() {
		b := []byte(`{"kind":"host-local-v1", "value":{"id": "asdfasdf", "if": "eth1"}}`)

		key, kind, err := ReadKey(b)
		Expect(err).NotTo(HaveOccurred())

		Expect(kind).To(BeEquivalentTo(KindReservationV1))

		Expect(key).To(Equal(&backend.Key{ID: "asdfasdf", IF: "eth1"}))
	})

	It("fails other kinds", func() {
		b := []byte(`{"kind":"host-local-v99", "value":{"id": "asdfasdf", "if": "eth1"}}`)
		key, kind, err := ReadKey(b)
		Expect(key).To(BeNil())
		Expect(kind).To(BeEmpty())
		Expect(err).To(MatchError("unknown key kind host-local-v99"))
	})
})
