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

package main

import (
	"fmt"

	"github.com/containernetworking/cni/pkg/ns"
	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/testutils"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("base functionality", func() {
	var targetNs ns.NetNS

	BeforeEach(func() {
		var err error
		targetNs, err = ns.NewNS()
		Expect(err).NotTo(HaveOccurred())
	})

	AfterEach(func() {
		targetNs.Close()
	})

	It("Works with a valid config", func() {
		ifname := "eth0"
		conf := `{
	"name": "cni-plugin-host-device-test",
	"type": "host-device",
	"device": "eth0"
}`
		conf = fmt.Sprintf(conf, ifname, targetNs.Path())
		args := &skel.CmdArgs{
			ContainerID: "dummy",
			Netns:       targetNs.Path(),
			IfName:      ifname,
			StdinData:   []byte(conf),
		}
		_, _, err := testutils.CmdAddWithResult(targetNs.Path(), "eth0", []byte(conf), func() error { return cmdAdd(args) })
		Expect(err).NotTo(HaveOccurred())

	})

	It("fails an invalid config", func() {
		conf := `{
	"cniVersion": "0.3.0",
	"name": "cni-plugin-sample-test",
	"type": "host-device"
}`

		args := &skel.CmdArgs{
			ContainerID: "dummy",
			Netns:       targetNs.Path(),
			IfName:      "eth0",
			StdinData:   []byte(conf),
		}
		_, _, err := testutils.CmdAddWithResult(targetNs.Path(), "eth0", []byte(conf), func() error { return cmdAdd(args) })
		Expect(err).To(MatchError("anotherAwesomeArg must be specified"))

	})

})
