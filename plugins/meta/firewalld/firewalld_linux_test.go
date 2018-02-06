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
	"fmt"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/plugins/pkg/firewalld"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/containernetworking/plugins/pkg/testutils"
	"github.com/godbus/dbus"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

const (
	confTmpl = `{
  "cniVersion": "0.3.1",
  "name": "firewalld-test",
  "type": "firewalld",
  "zone": "trusted",
  "prevResult": {
    "cniVersion": "0.3.0",
    "interfaces": [
      {"name": "%s", "sandbox": "%s"}
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
}`
	ifname = "eth0"
)

var _ = Describe("firewalld test", func() {
	var targetNs ns.NetNS

	BeforeEach(func() {
		var err error
		targetNs, err = ns.NewNS()
		Expect(err).NotTo(HaveOccurred())
	})

	It("works with a 0.3.1 config", func() {
		conn, err := dbus.SystemBus()
		Expect(err).NotTo(HaveOccurred())
		if !firewalld.IsRunning(conn) {
			Skip("firewalld service is not running, cannot test this plugin")
		}

		conf := fmt.Sprintf(confTmpl, ifname, targetNs.Path())
		args := &skel.CmdArgs{
			ContainerID: "dummy",
			Netns:       targetNs.Path(),
			IfName:      ifname,
			StdinData:   []byte(conf),
		}
		_, _, err = testutils.CmdAddWithResult(targetNs.Path(), ifname, []byte(conf), func() error { return cmdAdd(args) })
		Expect(err).NotTo(HaveOccurred())
		err = testutils.CmdDelWithResult(targetNs.Path(), ifname, func() error { return cmdDel(args) })
		Expect(err).NotTo(HaveOccurred())
	})
})
