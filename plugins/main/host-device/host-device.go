// Copyright 2015 CNI authors
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
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/cni/pkg/types/current"
	"github.com/containernetworking/cni/pkg/version"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/vishvananda/netlink"
)

type NetConf struct {
	types.NetConf
	Device     string `json:"device"`     // Device-Name, something like eth0 or can0 etc.
	HWAddr     string `json:"hwaddr"`     // MAC Address of target network interface
	KernelPath string `json:"kernelpath"` // Kernelpath of the device
}

func init() {
	// this ensures that main runs only on main thread (thread group leader).
	// since namespace ops (unshare, setns) are done for a single thread, we
	// must ensure that the goroutine does not jump from OS thread to thread
	runtime.LockOSThread()
}

func loadConf(bytes []byte) (*NetConf, error) {
	n := &NetConf{}
	if err := json.Unmarshal(bytes, n); err != nil {
		return nil, fmt.Errorf("failed to load netconf: %v", err)
	}
	if n.Device == "" && n.HWAddr == "" && n.KernelPath == "" {
		return nil, fmt.Errorf(`specify either "device", "hwaddr" or "kernelpath"`)
	}
	return n, nil
}

func cmdAdd(args *skel.CmdArgs) error {
	cfg, err := loadConf(args.StdinData)
	if err != nil {
		return err
	}
	containerNs, err := ns.GetNS(args.Netns)
	if err != nil {
		return fmt.Errorf("failed to open netns %q: %v", args.Netns, err)
	}
	defer containerNs.Close()

	dev, err := moveLinkIn(cfg.Device, cfg.HWAddr, cfg.KernelPath, containerNs)
	if err != nil {
		return fmt.Errorf("failed to move link %v", err)
	}
	return printLink(dev, cfg.CNIVersion, containerNs)
}

func cmdDel(args *skel.CmdArgs) error {
	cfg, err := loadConf(args.StdinData)
	if err != nil {
		return err
	}
	containerNs, err := ns.GetNS(args.Netns)
	if err != nil {
		return fmt.Errorf("failed to open netns %q: %v", args.Netns, err)
	}
	defer containerNs.Close()
	defer fmt.Println(`{}`)
	return moveLinkOut(cfg.Device, cfg.HWAddr, cfg.KernelPath, containerNs)
}

func moveLinkIn(device, hwAddr, kernelPath string, containerNs ns.NetNS) (netlink.Link, error) {
	dev, err := getLink(device, hwAddr, kernelPath)
	if err != nil {
		return nil, err
	}
	if err := netlink.LinkSetNsFd(dev, int(containerNs.Fd())); err != nil {
		return nil, err
	}

	if err := containerNs.Do(func(_ ns.NetNS) error {
		dev, err = netlink.LinkByName(dev.Attrs().Name)
		if err != nil {
			return err
		}
		return nil
	}); err != nil {
		return nil, err
	}

	return dev, nil
}

func moveLinkOut(device, hwAddr, kernelPath string, containerNs ns.NetNS) error {
	defaultNs, err := ns.GetCurrentNS()
	if err != nil {
		return err
	}

	return containerNs.Do(func(_ ns.NetNS) error {
		dev, err := getLink(device, hwAddr, kernelPath)
		if err != nil {
			return err
		}
		return netlink.LinkSetNsFd(dev, int(defaultNs.Fd()))
	})
}

func printLink(dev netlink.Link, cniVersion string, containerNs ns.NetNS) error {
	result := current.Result{
		CNIVersion: current.ImplementedSpecVersion,
		Interfaces: []*current.Interface{
			{
				Name:    dev.Attrs().Name,
				Mac:     dev.Attrs().HardwareAddr.String(),
				Sandbox: containerNs.Path(),
			},
		},
	}
	return types.PrintResult(&result, cniVersion)
}

func getLink(devname, hwaddr, kernelpath string) (netlink.Link, error) {
	links, err := netlink.LinkList()
	if err != nil {
		return nil, fmt.Errorf("failed to list node links: %v", err)
	}

	if len(devname) > 0 {
		return netlink.LinkByName(devname)
	} else if len(hwaddr) > 0 {
		hwAddr, err := net.ParseMAC(hwaddr)
		if err != nil {
			return nil, fmt.Errorf("failed to parse MAC address %q: %v", hwaddr, err)
		}

		for _, link := range links {
			if bytes.Equal(link.Attrs().HardwareAddr, hwAddr) {
				return link, nil
			}
		}
	} else if len(kernelpath) > 0 {
		if !filepath.IsAbs(kernelpath) || !strings.HasPrefix(kernelpath, "/sys/devices/") {
			return nil, fmt.Errorf("kernel device path %q must be absolute and begin with /sys/devices/", kernelpath)
		}
		netDir := filepath.Join(kernelpath, "net")
		files, err := ioutil.ReadDir(netDir)
		if err != nil {
			return nil, fmt.Errorf("failed to find network devices at %q", netDir)
		}

		// Grab the first device from eg /sys/devices/pci0000:00/0000:00:19.0/net
		for _, file := range files {
			// Make sure it's really an interface
			for _, l := range links {
				if file.Name() == l.Attrs().Name {
					return l, nil
				}
			}
		}
	}

	return nil, fmt.Errorf("failed to find physical interface")
}

func main() {
	skel.PluginMain(cmdAdd, cmdDel, version.All)
}
