// Copyright 2022 CNI authors
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
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/containernetworking/cni/libcni"
	types100 "github.com/containernetworking/cni/pkg/types/100"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/containernetworking/plugins/pkg/testutils"
)

// The integration tests expect the "firewall" binary to be present in $PATH.
// To run test, e.g, : go test -exec "sudo -E PATH=$(pwd):/opt/cni/bin:$PATH" -v -ginkgo.v
var _ = Describe("firewall integration tests (ingressPolicy: same-bridge)", func() {
	// ns0: foo (10.88.3.0/24)
	// ns1: foo (10.88.3.0/24)
	// ns2: bar (10.88.4.0/24)
	//
	// ns0@foo can talk to ns1@foo, but cannot talk to ns2@bar
	const nsCount = 3
	var (
		configListFoo *libcni.NetworkConfigList // "foo", 10.88.3.0/24
		configListBar *libcni.NetworkConfigList // "bar", 10.88.4.0/24
		cniConf       *libcni.CNIConfig
		namespaces    [nsCount]ns.NetNS
	)

	BeforeEach(func() {
		var err error
		rawConfigFoo := `
{
   "cniVersion": "1.0.0",
   "name": "foo",
   "plugins": [
      {
         "type": "bridge",
         "bridge": "foo",
         "isGateway": true,
         "ipMasq": true,
         "hairpinMode": true,
         "ipam": {
            "type": "host-local",
            "routes": [
               {
                  "dst": "0.0.0.0/0"
               }
            ],
            "ranges": [
               [
                  {
                     "subnet": "10.88.3.0/24",
                     "gateway": "10.88.3.1"
                  }
               ]
            ]
         }
      },
      {
         "type": "firewall",
         "backend": "iptables",
         "ingressPolicy": "same-bridge"
      }
   ]
}
`
		configListFoo, err = libcni.ConfListFromBytes([]byte(rawConfigFoo))
		Expect(err).NotTo(HaveOccurred())

		rawConfigBar := strings.ReplaceAll(rawConfigFoo, "foo", "bar")
		rawConfigBar = strings.ReplaceAll(rawConfigBar, "10.88.3.", "10.88.4.")

		configListBar, err = libcni.ConfListFromBytes([]byte(rawConfigBar))
		Expect(err).NotTo(HaveOccurred())

		// turn PATH in to CNI_PATH.
		_, err = exec.LookPath("firewall")
		Expect(err).NotTo(HaveOccurred())
		dirs := filepath.SplitList(os.Getenv("PATH"))
		cniConf = &libcni.CNIConfig{Path: dirs}

		for i := 0; i < nsCount; i++ {
			targetNS, err := testutils.NewNS()
			Expect(err).NotTo(HaveOccurred())
			fmt.Fprintf(GinkgoWriter, "namespace %d:%s\n", i, targetNS.Path())
			namespaces[i] = targetNS
		}
	})

	AfterEach(func() {
		for _, targetNS := range namespaces {
			if targetNS != nil {
				targetNS.Close()
			}
		}
	})

	Describe("Testing with network foo and bar", func() {
		It("should isolate foo from bar", func() {
			var results [nsCount]*types100.Result
			for i := 0; i < nsCount; i++ {
				runtimeConfig := libcni.RuntimeConf{
					ContainerID: fmt.Sprintf("test-cni-firewall-%d", i),
					NetNS:       namespaces[i].Path(),
					IfName:      "eth0",
				}

				configList := configListFoo
				switch i {
				case 0, 1:
				// leave foo
				default:
					configList = configListBar
				}

				// Clean up garbages produced during past failed executions
				_ = cniConf.DelNetworkList(context.TODO(), configList, &runtimeConfig)

				// Make delete idempotent, so we can clean up on failure
				netDeleted := false
				deleteNetwork := func() error {
					if netDeleted {
						return nil
					}
					netDeleted = true
					return cniConf.DelNetworkList(context.TODO(), configList, &runtimeConfig)
				}
				// Create the network
				res, err := cniConf.AddNetworkList(context.TODO(), configList, &runtimeConfig)
				Expect(err).NotTo(HaveOccurred())
				// nolint: errcheck
				defer deleteNetwork()

				results[i], err = types100.NewResultFromResult(res)
				Expect(err).NotTo(HaveOccurred())
				fmt.Fprintf(GinkgoWriter, "results[%d]: %+v\n", i, results[i])
			}
			ping := func(src, dst int) error {
				return namespaces[src].Do(func(ns.NetNS) error {
					defer GinkgoRecover()
					saddr := results[src].IPs[0].Address.IP.String()
					daddr := results[dst].IPs[0].Address.IP.String()
					srcNetName := results[src].Interfaces[0].Name
					dstNetName := results[dst].Interfaces[0].Name

					fmt.Fprintf(GinkgoWriter, "ping %s (ns%d@%s) -> %s (ns%d@%s)...",
						saddr, src, srcNetName, daddr, dst, dstNetName)
					timeoutSec := 1
					if err := testutils.Ping(saddr, daddr, timeoutSec); err != nil {
						fmt.Fprintln(GinkgoWriter, "unpingable")
						return err
					}
					fmt.Fprintln(GinkgoWriter, "pingable")
					return nil
				})
			}

			// ns0@foo can ping to ns1@foo
			err := ping(0, 1)
			Expect(err).NotTo(HaveOccurred())

			// ns1@foo can ping to ns0@foo
			err = ping(1, 0)
			Expect(err).NotTo(HaveOccurred())

			// ns0@foo cannot ping to ns2@bar
			err = ping(0, 2)
			Expect(err).To(HaveOccurred())

			// ns1@foo cannot ping to ns2@bar
			err = ping(1, 2)
			Expect(err).To(HaveOccurred())

			// ns2@bar cannot ping to ns0@foo
			err = ping(2, 0)
			Expect(err).To(HaveOccurred())

			// ns2@bar cannot ping to ns1@foo
			err = ping(2, 1)
			Expect(err).To(HaveOccurred())
		})
	})
})
