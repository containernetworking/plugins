package main

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"reflect"
	"syscall"
	"time"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types/current"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/containernetworking/plugins/pkg/testutils"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/vishvananda/netlink"
)

func cleanup(d dnsNameFile) error {
	_ = d.stop()
	return os.RemoveAll(filepath.Dir(d.PidFile))
}

var _ = Describe("dnsname tests", func() {
	var originalNS, targetNS ns.NetNS
	const IFNAME string = "dummy0"

	fullConf := []byte(`{
  "cniVersion": "0.4.0",
  "name": "test",
  "type": "dnsname",
  "domainName": "foobar.io",
  "prevResult": {
    "cniVersion": "0.4.0",
    "interfaces": [
      {
        "name": "dummy0",
        "mac": "a6:a7:ca:6b:34:2e"
      },
      {
        "name": "vetha0a83b38",
        "mac": "9a:45:bd:b0:2d:dd"
      },
      {
        "name": "eth0",
        "mac": "ea:63:0e:63:3e:86",
        "sandbox": "/var/run/netns/baude"
      }
    ],
    "ips": [
      {
        "version": "4",
        "interface": 2,
        "address": "10.88.8.5/24",
        "gateway": "10.88.8.1"
      }
    ],
    "routes": [
      {
        "dst": "0.0.0.0/0"
      }
    ]
}
	}`)

	BeforeEach(func() {
		// Create a new NetNS so we don't modify the host
		var err error
		originalNS, err = testutils.NewNS()
		Expect(err).NotTo(HaveOccurred())

		err = originalNS.Do(func(ns.NetNS) error {
			defer GinkgoRecover()

			err = netlink.LinkAdd(&netlink.Dummy{
				LinkAttrs: netlink.LinkAttrs{
					Name: IFNAME,
				},
			})
			Expect(err).NotTo(HaveOccurred())
			_, err = netlink.LinkByName(IFNAME)
			Expect(err).NotTo(HaveOccurred())
			return nil
		})
		Expect(err).NotTo(HaveOccurred())

		targetNS, err = testutils.NewNS()
		Expect(err).NotTo(HaveOccurred())
	})

	AfterEach(func() {
		Expect(originalNS.Close()).To(Succeed())
		Expect(targetNS.Close()).To(Succeed())
	})

	It("dnsname add", func() {
		args := &skel.CmdArgs{
			ContainerID: "dummy",
			Netns:       targetNS.Path(),
			IfName:      IFNAME,
			StdinData:   fullConf,
		}

		err := originalNS.Do(func(ns.NetNS) error {
			defer GinkgoRecover()

			r, _, err := testutils.CmdAdd(targetNS.Path(), args.ContainerID, IFNAME, fullConf, func() error {
				return cmdAdd(args)
			})
			Expect(err).NotTo(HaveOccurred())

			_, err = current.GetResult(r)
			Expect(err).NotTo(HaveOccurred())

			// Check that all configuration files are created
			files, err := ioutil.ReadDir("/run/containers/cni/dnsname/test")
			Expect(err).To(BeNil())
			expectedFileNames := []string{"addnhosts", "dnsmasq.conf", "lock", "pidfile"}
			var resultingFileNames []string
			for _, f := range files {
				resultingFileNames = append(resultingFileNames, f.Name())
			}
			Expect(reflect.DeepEqual(expectedFileNames, resultingFileNames)).To(BeTrue())

			d, err := newDNSMasqFile("foobar.io", "dummy0", "test")
			Expect(err).To(BeNil())

			// Check that the dns masq instance is running
			pid, err := d.getPidProcess()
			Expect(err).To(BeNil())
			// Send it a signal 0; if alive, error will be nil
			err = pid.Signal(syscall.Signal(0))
			Expect(err).To(BeNil())

			// Stop the dnsmasq instance and clean up files in the filesystem
			Expect(cleanup(d)).To(BeNil())
			return nil
		})
		Expect(err).NotTo(HaveOccurred())
	})

	It("dnsname del", func() {
		var (
			dnsDead bool
			counter int
		)
		args := &skel.CmdArgs{
			ContainerID: "dummy",
			Netns:       targetNS.Path(),
			IfName:      IFNAME,
			StdinData:   fullConf,
		}

		err := originalNS.Do(func(ns.NetNS) error {
			defer GinkgoRecover()

			r, _, err := testutils.CmdAdd(targetNS.Path(), args.ContainerID, IFNAME, fullConf, func() error {
				return cmdAdd(args)
			})
			Expect(err).NotTo(HaveOccurred())

			_, err = current.GetResult(r)
			Expect(err).NotTo(HaveOccurred())

			d, err := newDNSMasqFile("foobar.io", "dummy0", "test")
			Expect(err).To(BeNil())

			pid, err := d.getPidProcess()
			Expect(err).To(BeNil())
			err = pid.Signal(syscall.Signal(0))
			Expect(err).To(BeNil())

			err = testutils.CmdDel(targetNS.Path(), args.ContainerID, IFNAME, func() error {
				return cmdDel(args)
			})
			Expect(err).To(BeNil())

			// Ensure the dnsmasq instance has been stopped on del
			// It sometimes takes time for the dnsmasq pid to be killed
			// check every .5 second for maximum of 10 tries
			for {
				err = pid.Signal(syscall.Signal(0))
				if err != nil {
					dnsDead = true
					break
				}
				if counter == 10 {
					break
				}
				counter++
				time.Sleep(500 * time.Millisecond)
			}

			Expect(dnsDead).To(BeTrue())

			// Cleanup behind ourselves
			Expect(cleanup(d)).To(BeNil())
			return nil
		})
		Expect(err).NotTo(HaveOccurred())
	})
})
