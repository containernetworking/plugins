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

package main

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("firewalld configuration", func() {
	It("correctly parses an ADD config", func() {
		stdin := []byte(`{
  "cniVersion": "0.3.1",
  "name": "firewalld-test",
  "type": "firewalld",
  "zone": "trusted",
  "prevResult": {
    "interfaces": [
      {"name": "container", "sandbox": "netns"}
    ],
    "ips": [
      {
        "version": "4",
        "address": "10.0.0.2/24",
        "gateway": "10.0.0.1",
        "interface": 0
      }
    ],
    "routes": []
  }
}`)
		conf, err := parseConfig(stdin)
		Expect(err).NotTo(HaveOccurred())
		Expect(conf.CNIVersion).To(Equal("0.3.1"))
		Expect(conf.Zone).To(Equal("trusted"))
	})

	It("correctly parses a DEL config", func() {
		stdin := []byte(`{
  "cniVersion": "0.3.1",
  "type": "firewalld"
}`)
		conf, err := parseConfig(stdin)
		Expect(err).NotTo(HaveOccurred())
		Expect(conf.CNIVersion).To(Equal("0.3.1"))
	})
})
