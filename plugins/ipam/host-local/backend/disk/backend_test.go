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
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"

	"github.com/containernetworking/plugins/plugins/ipam/host-local/backend"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Disk backend test suite", func() {

	var store *Store
	var tmpDir string
	var netDir string

	BeforeEach(func() {
		var err error
		tmpDir, err = ioutil.TempDir("", "host_local_artifacts")
		Expect(err).NotTo(HaveOccurred())
		tmpDir = filepath.ToSlash(tmpDir)
		netDir = filepath.Join(tmpDir, "netname")

		store, err = New("netname", tmpDir)
		Expect(err).NotTo(HaveOccurred())
	})

	AfterEach(func() {
		if tmpDir != "" {
			os.RemoveAll(tmpDir)
		}
	})

	It("writes the correct reservation file", func() {
		id := backend.Key{ID: "asdf", IF: "eth1"}

		ok, err := store.Reserve(id, ip("10.0.0.1"), "1")
		Expect(err).NotTo(HaveOccurred())
		Expect(ok).To(BeTrue())

		res, err := ioutil.ReadFile(GetEscapedPath(netDir, "10.0.0.1"))
		Expect(err).NotTo(HaveOccurred())
		Expect(res).To(MatchJSON([]byte(`{"kind":"host-local-v1","value":{"id":"asdf","if":"eth1"}}`)))

		ok, err = store.Reserve(id, ip("10.0.0.1"), "1")
		Expect(err).NotTo(HaveOccurred())
		Expect(ok).To(BeFalse())
	})

	It("treats v0 reservations as reserved", func() {
		err := ioutil.WriteFile(GetEscapedPath(netDir, "10.0.0.2"), []byte("asdf"), 0644)
		Expect(err).NotTo(HaveOccurred())

		id := backend.Key{ID: "asdf", IF: "eth1"}
		ok, err := store.Reserve(id, ip("10.0.0.2"), "1")
		Expect(err).NotTo(HaveOccurred())
		Expect(ok).To(BeFalse())
	})

	It("cleans up v0 and v1 reservations", func() {
		// write a v0 with the same and different container ids
		err := ioutil.WriteFile(GetEscapedPath(netDir, "10.0.0.2"), []byte("id1"), 0644)
		Expect(err).NotTo(HaveOccurred())

		err = ioutil.WriteFile(GetEscapedPath(netDir, "10.0.0.3"), []byte("id2"), 0644)
		Expect(err).NotTo(HaveOccurred())

		// write a v1 with same and different ids, and same and different ifs
		err = ioutil.WriteFile(GetEscapedPath(netDir, "10.0.0.4"), WriteKey(&backend.Key{ID: "id1", IF: "eth0"}), 0644)
		Expect(err).NotTo(HaveOccurred())

		err = ioutil.WriteFile(GetEscapedPath(netDir, "10.0.0.5"), WriteKey(&backend.Key{ID: "id1", IF: "eth1"}), 0644)
		Expect(err).NotTo(HaveOccurred())

		// different container id
		err = ioutil.WriteFile(GetEscapedPath(netDir, "10.0.0.6"), WriteKey(&backend.Key{ID: "id2", IF: "eth0"}), 0644)
		Expect(err).NotTo(HaveOccurred())

		err = ioutil.WriteFile(GetEscapedPath(netDir, "10.0.0.7"), WriteKey(&backend.Key{ID: "id2", IF: "eth1"}), 0644)
		Expect(err).NotTo(HaveOccurred())

		k := backend.Key{ID: "id1", IF: "eth0"}

		ips, err := store.GetByID(k)
		Expect(err).NotTo(HaveOccurred())
		Expect(ips).To(ConsistOf(
			net.ParseIP("10.0.0.2"),
			net.ParseIP("10.0.0.4"),
		))

		store.ReleaseByID(k)

		// now when we clean up id1:eth0, we expect to have
		// .3, .5, .6, and .7
		for _, tc := range []struct {
			ip    string
			exist bool
		}{
			{"10.0.0.2", false},
			{"10.0.0.3", true},
			{"10.0.0.4", false},
			{"10.0.0.5", true},
			{"10.0.0.6", true},
			{"10.0.0.7", true},
		} {
			path := GetEscapedPath(netDir, tc.ip)
			_, err := os.Stat(path)
			if tc.exist && err != nil {
				Fail(fmt.Sprintf("Expected %s to exist", path))
			} else if !tc.exist && err == nil {
				Fail(fmt.Sprintf("Expected %s not to exist", path))
			}
		}

	})

})

func ip(ip string) net.IP {
	i := net.ParseIP(ip)
	Expect(i).NotTo(BeEmpty())
	return i
}
