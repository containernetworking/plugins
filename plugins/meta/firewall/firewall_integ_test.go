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

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/containernetworking/cni/libcni"
	types100 "github.com/containernetworking/cni/pkg/types/100"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/containernetworking/plugins/pkg/testutils"
)

const nsCount = 3

// The integration tests expect the "firewall" binary to be present in $PATH.
// To run test, e.g, : go test -exec "sudo -E PATH=$(pwd):/opt/cni/bin:$PATH" -v -ginkgo.v
var _ = Describe("firewall integration tests (ingressPolicy: same-bridge)", func() {
	// ns0: foo (10.88.3.0/24)
	// ns1: foo (10.88.3.0/24)
	// ns2: bar (10.88.4.0/24)
	//
	// ns0@foo can talk to ns1@foo, but cannot talk to ns2@bar

	var (
		configListFoo *libcni.NetworkConfigList // "foo", 10.88.3.0/24
		configListBar *libcni.NetworkConfigList // "bar", 10.88.4.0/24
		cniConf       *libcni.CNIConfig
		namespaces    [nsCount]ns.NetNS
		results       [nsCount]*types100.Result
	)

	createNetworkConfig := func(name string, subnet string, gateway string, ingressPolicy string) string {
		return fmt.Sprintf(`{
   "cniVersion": "1.0.0",
   "name": "%s",
   "plugins": [
      {
         "type": "bridge",
         "bridge": "%s",
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
                     "subnet": "%s",
                     "gateway": "%s"
                  }
               ]
            ]
         }
      },
      {
         "type": "firewall",
         "backend": "iptables",
         "ingressPolicy": "%s"
      }
   ]
}`, name, name, subnet, gateway, ingressPolicy)
	}

	BeforeEach(func() {
		var err error

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

	Describe("Testing with ingress-policy 'same-bridge", func() {
		BeforeEach(func() {
			var err error
			configListFoo, err = libcni.ConfListFromBytes([]byte(
				createNetworkConfig("foo", "10.88.3.0/24", "10.88.3.1", "same-bridge")))
			Expect(err).NotTo(HaveOccurred())

			configListBar, err = libcni.ConfListFromBytes([]byte(
				createNetworkConfig("bar", "10.88.4.0/24", "10.88.4.1", "same-bridge")))
			Expect(err).NotTo(HaveOccurred())

			results = setupNetworks(cniConf, namespaces, configListFoo, configListBar)
		})

		Context("when testing connectivity", func() {
			It("should allow communication within foo network", func() {
				err := ping(namespaces, results, 0, 1)
				Expect(err).To(Succeed())
				err = ping(namespaces, results, 1, 0)
				Expect(err).To(Succeed())
			})

			It("should prevent communication between foo and bar networks", func() {
				err := ping(namespaces, results, 0, 2)
				Expect(err).To(HaveOccurred())
				err = ping(namespaces, results, 1, 2)
				Expect(err).To(HaveOccurred())
				err = ping(namespaces, results, 2, 0)
				Expect(err).To(HaveOccurred())
				err = ping(namespaces, results, 2, 1)
				Expect(err).To(HaveOccurred())
			})
		})
	})

	Describe("Testing with ingress-policy 'isolated", func() {
		BeforeEach(func() {
			var err error
			configListFoo, err = libcni.ConfListFromBytes([]byte(
				createNetworkConfig("foo", "10.88.3.0/24", "10.88.3.1", "isolated")))
			Expect(err).NotTo(HaveOccurred())

			configListBar, err = libcni.ConfListFromBytes([]byte(
				createNetworkConfig("bar", "10.88.4.0/24", "10.88.4.1", "isolated")))
			Expect(err).NotTo(HaveOccurred())

			results = setupNetworks(cniConf, namespaces, configListFoo, configListBar)
		})

		Context("when testing connectivity", func() {
			It("should prevent communication within foo network", func() {
				err := ping(namespaces, results, 0, 1)
				Expect(err).To(HaveOccurred())
				err = ping(namespaces, results, 1, 0)
				Expect(err).To(HaveOccurred())
			})

			It("should prevent communication between foo and bar networks", func() {
				err := ping(namespaces, results, 0, 2)
				Expect(err).To(HaveOccurred())
				err = ping(namespaces, results, 1, 2)
				Expect(err).To(HaveOccurred())
				err = ping(namespaces, results, 2, 0)
				Expect(err).To(HaveOccurred())
				err = ping(namespaces, results, 2, 1)
				Expect(err).To(HaveOccurred())
			})
		})
	})
})

func setupNetworks(cniConf *libcni.CNIConfig, namespaces [nsCount]ns.NetNS,
	configListFoo, configListBar *libcni.NetworkConfigList,
) [nsCount]*types100.Result {
	var results [nsCount]*types100.Result

	for i := 0; i < nsCount; i++ {
		runtimeConfig := libcni.RuntimeConf{
			ContainerID: fmt.Sprintf("test-cni-firewall-%d", i),
			NetNS:       namespaces[i].Path(),
			IfName:      "eth0",
		}

		configList := configListFoo
		if i >= 2 {
			configList = configListBar
		}

		// Cleanup any existing network
		_ = cniConf.DelNetworkList(context.TODO(), configList, &runtimeConfig)

		// Create network
		res, err := cniConf.AddNetworkList(context.TODO(), configList, &runtimeConfig)
		Expect(err).NotTo(HaveOccurred())

		// Setup cleanup
		DeferCleanup(func() {
			_ = cniConf.DelNetworkList(context.TODO(), configList, &runtimeConfig)
		})

		results[i], err = types100.NewResultFromResult(res)
		Expect(err).NotTo(HaveOccurred())
	}

	return results
}

func ping(namespaces [nsCount]ns.NetNS, results [nsCount]*types100.Result, src, dst int) error {
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
