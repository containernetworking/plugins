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
	"bufio"
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"syscall"

	"github.com/godbus/dbus/v5"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/containernetworking/cni/pkg/invoke"
	"github.com/containernetworking/cni/pkg/skel"
	current "github.com/containernetworking/cni/pkg/types/100"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/containernetworking/plugins/pkg/testutils"
)

const ifname = "eth0"

type fakeFirewalld struct {
	zone   string
	source string
}

func (f *fakeFirewalld) clear() {
	f.zone = ""
	f.source = ""
}

//nolint:unparam
func (f *fakeFirewalld) AddSource(zone, source string) (string, *dbus.Error) {
	f.zone = zone
	f.source = source
	return "", nil
}

//nolint:unparam
func (f *fakeFirewalld) RemoveSource(zone, source string) (string, *dbus.Error) {
	f.zone = zone
	f.source = source
	return "", nil
}

//nolint:unparam
func (f *fakeFirewalld) QuerySource(zone, source string) (bool, *dbus.Error) {
	if f.zone != zone {
		return false, nil
	}
	if f.source != source {
		return false, nil
	}
	return true, nil
}

func spawnSessionDbus(wg *sync.WaitGroup) (string, *exec.Cmd) {
	// Start a private D-Bus session bus
	path, err := invoke.FindInPath("dbus-daemon", []string{
		"/bin", "/sbin", "/usr/bin", "/usr/sbin",
	})
	Expect(err).NotTo(HaveOccurred())
	cmd := exec.Command(path, "--session", "--print-address", "--nofork", "--nopidfile")
	stdout, err := cmd.StdoutPipe()
	Expect(err).NotTo(HaveOccurred())
	err = cmd.Start()
	Expect(err).NotTo(HaveOccurred())

	// Wait for dbus-daemon to print the bus address
	bytes, err := bufio.NewReader(stdout).ReadString('\n')
	Expect(err).NotTo(HaveOccurred())
	busAddr := strings.TrimSpace(bytes)
	Expect(strings.HasPrefix(busAddr, "unix:abstract") ||
		strings.HasPrefix(busAddr, "unix:path")).To(BeTrue())

	var startWg sync.WaitGroup
	wg.Add(1)
	startWg.Add(1)
	go func() {
		defer GinkgoRecover()

		startWg.Done()
		err = cmd.Wait()
		Expect(err).NotTo(HaveOccurred())
		wg.Done()
	}()

	startWg.Wait()
	return busAddr, cmd
}

func makeFirewalldConf(ver string, ns ns.NetNS) []byte {
	return []byte(fmt.Sprintf(`{
	  "cniVersion": "%s",
	  "name": "firewalld-test",
	  "type": "firewall",
	  "backend": "firewalld",
	  "zone": "trusted",
	  "prevResult": {
	    "cniVersion": "%s",
	    "interfaces": [
	      {"name": "eth0", "sandbox": "%s"}
	    ],
	    "ips": [
	      {
		"version": "4",
		"address": "10.0.0.2/24",
		"gateway": "10.0.0.1",
		"interface": 0
	      }
	    ]
	  }
	}`, ver, ver, ns.Path()))
}

var _ = Describe("firewalld test", func() {
	var (
		targetNs ns.NetNS
		cmd      *exec.Cmd
		conn     *dbus.Conn
		wg       sync.WaitGroup
		fwd      *fakeFirewalld
		busAddr  string
	)

	BeforeEach(func() {
		var err error
		targetNs, err = testutils.NewNS()
		Expect(err).NotTo(HaveOccurred())

		// Start a private D-Bus session bus
		busAddr, cmd = spawnSessionDbus(&wg)
		conn, err = dbus.Dial(busAddr)
		Expect(err).NotTo(HaveOccurred())
		err = conn.Auth(nil)
		Expect(err).NotTo(HaveOccurred())
		err = conn.Hello()
		Expect(err).NotTo(HaveOccurred())

		// Start our fake firewalld
		reply, err := conn.RequestName(firewalldName, dbus.NameFlagDoNotQueue)
		Expect(err).NotTo(HaveOccurred())
		Expect(reply).To(Equal(dbus.RequestNameReplyPrimaryOwner))

		fwd = &fakeFirewalld{}
		// Because firewalld D-Bus methods start with lower-case, and
		// because in Go lower-case methods are private, we need to remap
		// Go public methods to the D-Bus name
		methods := map[string]string{
			"AddSource":    firewalldAddSourceMethod,
			"QuerySource":  firewalldQuerySourceMethod,
			"RemoveSource": firewalldRemoveSourceMethod,
		}
		conn.ExportWithMap(fwd, methods, firewalldPath, firewalldZoneInterface)

		// Make sure the plugin uses our private session bus
		testConn = conn
	})

	AfterEach(func() {
		_, err := conn.ReleaseName(firewalldName)
		Expect(err).NotTo(HaveOccurred())

		err = cmd.Process.Signal(syscall.SIGTERM)
		Expect(err).NotTo(HaveOccurred())

		wg.Wait()

		Expect(targetNs.Close()).To(Succeed())
		Expect(testutils.UnmountNS(targetNs)).To(Succeed())
	})

	// firewall plugin requires a prevResult and thus only supports 0.3.0
	// and later CNI versions
	for _, ver := range []string{"0.3.0", "0.3.1", "0.4.0", "1.0.0"} {
		// Redefine ver inside for scope so real value is picked up by each dynamically defined It()
		// See Gingkgo's "Patterns for dynamically generating tests" documentation.
		ver := ver

		It(fmt.Sprintf("[%s] works with a config", ver), func() {
			Expect(isFirewalldRunning()).To(BeTrue())

			conf := makeFirewalldConf(ver, targetNs)
			args := &skel.CmdArgs{
				ContainerID: "dummy",
				Netns:       targetNs.Path(),
				IfName:      ifname,
				StdinData:   conf,
			}
			_, _, err := testutils.CmdAdd(targetNs.Path(), args.ContainerID, ifname, conf, func() error {
				return cmdAdd(args)
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(fwd.zone).To(Equal("trusted"))
			Expect(fwd.source).To(Equal("10.0.0.2/32"))
			fwd.clear()

			err = testutils.CmdDel(targetNs.Path(), args.ContainerID, ifname, func() error {
				return cmdDel(args)
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(fwd.zone).To(Equal("trusted"))
			Expect(fwd.source).To(Equal("10.0.0.2/32"))
		})

		It(fmt.Sprintf("[%s] defaults to the firewalld backend", ver), func() {
			Expect(isFirewalldRunning()).To(BeTrue())

			conf := makeFirewalldConf(ver, targetNs)
			args := &skel.CmdArgs{
				ContainerID: "dummy",
				Netns:       targetNs.Path(),
				IfName:      ifname,
				StdinData:   conf,
			}
			_, _, err := testutils.CmdAdd(targetNs.Path(), args.ContainerID, ifname, conf, func() error {
				return cmdAdd(args)
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(fwd.zone).To(Equal("trusted"))
			Expect(fwd.source).To(Equal("10.0.0.2/32"))
		})

		It(fmt.Sprintf("[%s] passes through the prevResult", ver), func() {
			Expect(isFirewalldRunning()).To(BeTrue())

			conf := makeFirewalldConf(ver, targetNs)
			args := &skel.CmdArgs{
				ContainerID: "dummy",
				Netns:       targetNs.Path(),
				IfName:      ifname,
				StdinData:   conf,
			}
			r, _, err := testutils.CmdAdd(targetNs.Path(), args.ContainerID, ifname, conf, func() error {
				return cmdAdd(args)
			})
			Expect(err).NotTo(HaveOccurred())

			result, err := current.GetResult(r)
			Expect(err).NotTo(HaveOccurred())

			Expect(result.Interfaces).To(HaveLen(1))
			Expect(result.Interfaces[0].Name).To(Equal("eth0"))
			Expect(result.IPs).To(HaveLen(1))
			Expect(result.IPs[0].Address.String()).To(Equal("10.0.0.2/24"))
		})

		It(fmt.Sprintf("[%s] works with Check", ver), func() {
			Expect(isFirewalldRunning()).To(BeTrue())

			conf := makeFirewalldConf(ver, targetNs)
			args := &skel.CmdArgs{
				ContainerID: "dummy",
				Netns:       targetNs.Path(),
				IfName:      ifname,
				StdinData:   conf,
			}
			r, _, err := testutils.CmdAddWithArgs(args, func() error {
				return cmdAdd(args)
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(fwd.zone).To(Equal("trusted"))
			Expect(fwd.source).To(Equal("10.0.0.2/32"))

			if testutils.SpecVersionHasCHECK(ver) {
				_, err = current.GetResult(r)
				Expect(err).NotTo(HaveOccurred())

				err = testutils.CmdCheckWithArgs(args, func() error {
					return cmdCheck(args)
				})
				Expect(err).NotTo(HaveOccurred())
			}

			err = testutils.CmdDelWithArgs(args, func() error {
				return cmdDel(args)
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(fwd.zone).To(Equal("trusted"))
			Expect(fwd.source).To(Equal("10.0.0.2/32"))
		})
	}
})
