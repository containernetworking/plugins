// Copyright 2026 CNI authors
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
	"net"
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/containernetworking/cni/pkg/types"
)

var _ = Describe("Store GC", func() {
	const network = "gcnet"

	var (
		dataDir string
		store   *Store
	)

	BeforeEach(func() {
		var err error
		dataDir, err = os.MkdirTemp("", "host_local_gc")
		Expect(err).NotTo(HaveOccurred())
		store, err = New(network, dataDir)
		Expect(err).NotTo(HaveOccurred())
	})

	AfterEach(func() {
		Expect(store.Close()).To(Succeed())
		Expect(os.RemoveAll(dataDir)).To(Succeed())
	})

	// reserved writes a reservation the way Reserve does, so the tests exercise
	// the real on-disk format rather than a guess at it.
	reserved := func(ip, id, ifname string) {
		ok, err := store.Reserve(id, ifname, net.ParseIP(ip), "0")
		Expect(err).NotTo(HaveOccurred())
		Expect(ok).To(BeTrue())
	}

	exists := func(name string) bool {
		_, err := os.Stat(filepath.Join(dataDir, network, name))
		return err == nil
	}

	It("releases reservations that are not in the valid set", func() {
		reserved("10.0.0.1", "keep-me", "eth0")
		reserved("10.0.0.2", "gone", "eth0")

		Expect(store.GC([]types.GCAttachment{
			{ContainerID: "keep-me", IfName: "eth0"},
		})).To(Succeed())

		Expect(exists("10.0.0.1")).To(BeTrue(), "valid attachment was released")
		Expect(exists("10.0.0.2")).To(BeFalse(), "stale attachment was kept")
	})

	It("matches on the interface as well as the container", func() {
		// The same container holding two interfaces is two attachments. A
		// runtime that reports only one of them wants the other released.
		reserved("10.0.0.1", "twoif", "eth0")
		reserved("10.0.0.2", "twoif", "eth1")

		Expect(store.GC([]types.GCAttachment{
			{ContainerID: "twoif", IfName: "eth0"},
		})).To(Succeed())

		Expect(exists("10.0.0.1")).To(BeTrue())
		Expect(exists("10.0.0.2")).To(BeFalse(), "released only by container, ignoring ifname")
	})

	It("releases everything when the valid set is empty", func() {
		reserved("10.0.0.1", "a", "eth0")
		reserved("10.0.0.2", "b", "eth0")

		Expect(store.GC(nil)).To(Succeed())

		Expect(exists("10.0.0.1")).To(BeFalse())
		Expect(exists("10.0.0.2")).To(BeFalse())
	})

	It("leaves the lock and last_reserved_ip bookkeeping files alone", func() {
		// Reserve writes last_reserved_ip.0, and New creates the lock. Both live
		// in the same directory as the reservations and are not reservations, so
		// a GC that just walks the directory would delete them.
		reserved("10.0.0.1", "gone", "eth0")

		Expect(store.GC(nil)).To(Succeed())

		Expect(exists("10.0.0.1")).To(BeFalse())
		Expect(exists("lock")).To(BeTrue(), "GC deleted the lock file")
		Expect(exists(lastIPFilePrefix+"0")).To(BeTrue(), "GC deleted last_reserved_ip")
	})

	It("understands reservations written before ifname was recorded", func() {
		// Older versions wrote just the container ID. ReleaseByID already falls
		// back to matching those, and GC has to agree or it would delete live
		// allocations on the first run after an upgrade.
		legacy := filepath.Join(dataDir, network, "10.0.0.9")
		Expect(os.WriteFile(legacy, []byte("legacy-id"), 0o600)).To(Succeed())

		Expect(store.GC([]types.GCAttachment{
			{ContainerID: "legacy-id", IfName: "eth0"},
		})).To(Succeed())

		Expect(exists("10.0.0.9")).To(BeTrue(), "legacy reservation was wrongly released")
	})

	It("still releases a legacy reservation that is genuinely stale", func() {
		legacy := filepath.Join(dataDir, network, "10.0.0.9")
		Expect(os.WriteFile(legacy, []byte("legacy-id"), 0o600)).To(Succeed())

		Expect(store.GC([]types.GCAttachment{
			{ContainerID: "someone-else", IfName: "eth0"},
		})).To(Succeed())

		Expect(exists("10.0.0.9")).To(BeFalse())
	})

	It("frees the address for reuse", func() {
		// The point of GC is reclaiming leaked reservations, so the freed
		// address has to actually be allocatable again.
		reserved("10.0.0.1", "leaked", "eth0")
		Expect(store.GC(nil)).To(Succeed())

		ok, err := store.Reserve("newcomer", "eth0", net.ParseIP("10.0.0.1"), "0")
		Expect(err).NotTo(HaveOccurred())
		Expect(ok).To(BeTrue(), "address was not reusable after GC")
	})
})
