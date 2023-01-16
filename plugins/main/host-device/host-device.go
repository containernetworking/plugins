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
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/vishvananda/netlink"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	current "github.com/containernetworking/cni/pkg/types/100"
	"github.com/containernetworking/cni/pkg/version"

	"github.com/containernetworking/plugins/pkg/ip"
	"github.com/containernetworking/plugins/pkg/ipam"
	"github.com/containernetworking/plugins/pkg/ns"
	bv "github.com/containernetworking/plugins/pkg/utils/buildversion"
)

var (
	sysBusPCI = "/sys/bus/pci/devices"
)

// Array of different linux drivers bound to network device needed for DPDK
var userspaceDrivers = []string{"vfio-pci", "uio_pci_generic", "igb_uio"}

// NetConf for host-device config, look the README to learn how to use those parameters
type NetConf struct {
	types.NetConf
	Device        string `json:"device"` // Device-Name, something like eth0 or can0 etc.
	HWAddr        string `json:"hwaddr"` // MAC Address of target network interface
	DPDKMode      bool
	KernelPath    string `json:"kernelpath"` // Kernelpath of the device
	PCIAddr       string `json:"pciBusID"`   // PCI Address of target network device
	RuntimeConfig struct {
		DeviceID string `json:"deviceID,omitempty"`
	} `json:"runtimeConfig,omitempty"`
}

func init() {
	// this ensures that main runs only on main thread (thread group leader).
	// since namespace ops (unshare, setns) are done for a single thread, we
	// must ensure that the goroutine does not jump from OS thread to thread
	runtime.LockOSThread()
}

func loadConf(bytes []byte) (*NetConf, error) {
	n := &NetConf{}
	var err error
	if err = json.Unmarshal(bytes, n); err != nil {
		return nil, fmt.Errorf("failed to load netconf: %v", err)
	}

	if n.RuntimeConfig.DeviceID != "" {
		// Override PCI device with the standardized DeviceID provided in Runtime Config.
		n.PCIAddr = n.RuntimeConfig.DeviceID
	}

	if n.Device == "" && n.HWAddr == "" && n.KernelPath == "" && n.PCIAddr == "" {
		return nil, fmt.Errorf(`specify either "device", "hwaddr", "kernelpath" or "pciBusID"`)
	}

	if len(n.PCIAddr) > 0 {
		n.DPDKMode, err = hasDpdkDriver(n.PCIAddr)
		if err != nil {
			return nil, fmt.Errorf("error with host device: %v", err)
		}
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

	result := &current.Result{}
	var contDev netlink.Link
	if !cfg.DPDKMode {
		hostDev, err := getLink(cfg.Device, cfg.HWAddr, cfg.KernelPath, cfg.PCIAddr)
		if err != nil {
			return fmt.Errorf("failed to find host device: %v", err)
		}

		contDev, err = moveLinkIn(hostDev, containerNs, args.IfName)
		if err != nil {
			return fmt.Errorf("failed to move link %v", err)
		}

		result.Interfaces = []*current.Interface{{
			Name:    contDev.Attrs().Name,
			Mac:     contDev.Attrs().HardwareAddr.String(),
			Sandbox: containerNs.Path(),
		}}
	}

	if cfg.IPAM.Type == "" {
		if cfg.DPDKMode {
			return types.PrintResult(result, cfg.CNIVersion)
		}
		return printLink(contDev, cfg.CNIVersion, containerNs)
	}

	// run the IPAM plugin and get back the config to apply
	r, err := ipam.ExecAdd(cfg.IPAM.Type, args.StdinData)
	if err != nil {
		return err
	}

	// Invoke ipam del if err to avoid ip leak
	defer func() {
		if err != nil {
			ipam.ExecDel(cfg.IPAM.Type, args.StdinData)
		}
	}()

	// Convert whatever the IPAM result was into the current Result type
	newResult, err := current.NewResultFromResult(r)
	if err != nil {
		return err
	}

	if len(newResult.IPs) == 0 {
		return errors.New("IPAM plugin returned missing IP config")
	}

	for _, ipc := range newResult.IPs {
		// All addresses apply to the container interface (move from host)
		ipc.Interface = current.Int(0)
	}

	newResult.Interfaces = result.Interfaces

	if !cfg.DPDKMode {
		err = containerNs.Do(func(_ ns.NetNS) error {
			if err := ipam.ConfigureIface(args.IfName, newResult); err != nil {
				return err
			}
			return nil
		})
		if err != nil {
			return err
		}
	}

	newResult.DNS = cfg.DNS

	return types.PrintResult(newResult, cfg.CNIVersion)
}

func cmdDel(args *skel.CmdArgs) error {
	cfg, err := loadConf(args.StdinData)
	if err != nil {
		return err
	}
	if args.Netns == "" {
		return nil
	}
	containerNs, err := ns.GetNS(args.Netns)
	if err != nil {
		return fmt.Errorf("failed to open netns %q: %v", args.Netns, err)
	}
	defer containerNs.Close()

	if cfg.IPAM.Type != "" {
		if err := ipam.ExecDel(cfg.IPAM.Type, args.StdinData); err != nil {
			return err
		}
	}

	if !cfg.DPDKMode {
		if err := moveLinkOut(containerNs, args.IfName); err != nil {
			return err
		}
	}

	return nil
}

func moveLinkIn(hostDev netlink.Link, containerNs ns.NetNS, ifName string) (netlink.Link, error) {
	if err := netlink.LinkSetNsFd(hostDev, int(containerNs.Fd())); err != nil {
		return nil, err
	}

	var contDev netlink.Link
	if err := containerNs.Do(func(_ ns.NetNS) error {
		var err error
		contDev, err = netlink.LinkByName(hostDev.Attrs().Name)
		if err != nil {
			return fmt.Errorf("failed to find %q: %v", hostDev.Attrs().Name, err)
		}
		// Devices can be renamed only when down
		if err = netlink.LinkSetDown(contDev); err != nil {
			return fmt.Errorf("failed to set %q down: %v", hostDev.Attrs().Name, err)
		}
		// Save host device name into the container device's alias property
		if err := netlink.LinkSetAlias(contDev, hostDev.Attrs().Name); err != nil {
			return fmt.Errorf("failed to set alias to %q: %v", hostDev.Attrs().Name, err)
		}
		// Rename container device to respect args.IfName
		if err := netlink.LinkSetName(contDev, ifName); err != nil {
			return fmt.Errorf("failed to rename device %q to %q: %v", hostDev.Attrs().Name, ifName, err)
		}
		// Bring container device up
		if err = netlink.LinkSetUp(contDev); err != nil {
			return fmt.Errorf("failed to set %q up: %v", ifName, err)
		}
		// Retrieve link again to get up-to-date name and attributes
		contDev, err = netlink.LinkByName(ifName)
		if err != nil {
			return fmt.Errorf("failed to find %q: %v", ifName, err)
		}
		return nil
	}); err != nil {
		return nil, err
	}

	return contDev, nil
}

func moveLinkOut(containerNs ns.NetNS, ifName string) error {
	defaultNs, err := ns.GetCurrentNS()
	if err != nil {
		return err
	}
	defer defaultNs.Close()

	return containerNs.Do(func(_ ns.NetNS) error {
		dev, err := netlink.LinkByName(ifName)
		if err != nil {
			return fmt.Errorf("failed to find %q: %v", ifName, err)
		}

		// Devices can be renamed only when down
		if err = netlink.LinkSetDown(dev); err != nil {
			return fmt.Errorf("failed to set %q down: %v", ifName, err)
		}

		defer func() {
			// If moving the device to the host namespace fails, set its name back to ifName so that this
			// function can be retried. Also bring the device back up, unless it was already down before.
			if err != nil {
				_ = netlink.LinkSetName(dev, ifName)
				if dev.Attrs().Flags&net.FlagUp == net.FlagUp {
					_ = netlink.LinkSetUp(dev)
				}
			}
		}()

		// Rename the device to its original name from the host namespace
		if err = netlink.LinkSetName(dev, dev.Attrs().Alias); err != nil {
			return fmt.Errorf("failed to restore %q to original name %q: %v", ifName, dev.Attrs().Alias, err)
		}

		if err = netlink.LinkSetNsFd(dev, int(defaultNs.Fd())); err != nil {
			return fmt.Errorf("failed to move %q to host netns: %v", dev.Attrs().Alias, err)
		}
		return nil
	})
}

func hasDpdkDriver(pciaddr string) (bool, error) {
	driverLink := filepath.Join(sysBusPCI, pciaddr, "driver")
	driverPath, err := filepath.EvalSymlinks(driverLink)
	if err != nil {
		return false, err
	}
	driverStat, err := os.Stat(driverPath)
	if err != nil {
		return false, err
	}
	driverName := driverStat.Name()
	for _, drv := range userspaceDrivers {
		if driverName == drv {
			return true, nil
		}
	}
	return false, nil
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

func getLink(devname, hwaddr, kernelpath, pciaddr string) (netlink.Link, error) {
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
		entries, err := os.ReadDir(netDir)
		if err != nil {
			return nil, fmt.Errorf("failed to find network devices at %q", netDir)
		}

		// Grab the first device from eg /sys/devices/pci0000:00/0000:00:19.0/net
		for _, entry := range entries {
			// Make sure it's really an interface
			for _, l := range links {
				if entry.Name() == l.Attrs().Name {
					return l, nil
				}
			}
		}
	} else if len(pciaddr) > 0 {
		netDir := filepath.Join(sysBusPCI, pciaddr, "net")
		if _, err := os.Lstat(netDir); err != nil {
			virtioNetDir := filepath.Join(sysBusPCI, pciaddr, "virtio*", "net")
			matches, err := filepath.Glob(virtioNetDir)
			if matches == nil || err != nil {
				return nil, fmt.Errorf("no net directory under pci device %s", pciaddr)
			}
			netDir = matches[0]
		}
		entries, err := os.ReadDir(netDir)
		if err != nil {
			return nil, fmt.Errorf("failed to read net directory %s: %q", netDir, err)
		}
		if len(entries) > 0 {
			return netlink.LinkByName(entries[0].Name())
		}
		return nil, fmt.Errorf("failed to find device name for pci address %s", pciaddr)
	}

	return nil, fmt.Errorf("failed to find physical interface")
}

func main() {
	skel.PluginMain(cmdAdd, cmdCheck, cmdDel, version.All, bv.BuildString("host-device"))
}

func cmdCheck(args *skel.CmdArgs) error {

	cfg, err := loadConf(args.StdinData)
	if err != nil {
		return err
	}
	netns, err := ns.GetNS(args.Netns)
	if err != nil {
		return fmt.Errorf("failed to open netns %q: %v", args.Netns, err)
	}
	defer netns.Close()

	// run the IPAM plugin and get back the config to apply
	if cfg.IPAM.Type != "" {
		err = ipam.ExecCheck(cfg.IPAM.Type, args.StdinData)
		if err != nil {
			return err
		}
	}

	// Parse previous result.
	if cfg.NetConf.RawPrevResult == nil {
		return fmt.Errorf("Required prevResult missing")
	}

	if err := version.ParsePrevResult(&cfg.NetConf); err != nil {
		return err
	}

	result, err := current.NewResultFromResult(cfg.PrevResult)
	if err != nil {
		return err
	}

	if cfg.DPDKMode {
		return nil
	}

	var contMap current.Interface
	// Find interfaces for name we know, that of host-device inside container
	for _, intf := range result.Interfaces {
		if args.IfName == intf.Name {
			if args.Netns == intf.Sandbox {
				contMap = *intf
				continue
			}
		}
	}

	// The namespace must be the same as what was configured
	if args.Netns != contMap.Sandbox {
		return fmt.Errorf("Sandbox in prevResult %s doesn't match configured netns: %s",
			contMap.Sandbox, args.Netns)
	}

	//
	// Check prevResults for ips, routes and dns against values found in the container
	if err := netns.Do(func(_ ns.NetNS) error {

		// Check interface against values found in the container
		err := validateCniContainerInterface(contMap)
		if err != nil {
			return err
		}

		err = ip.ValidateExpectedInterfaceIPs(args.IfName, result.IPs)
		if err != nil {
			return err
		}

		err = ip.ValidateExpectedRoute(result.Routes)
		if err != nil {
			return err
		}
		return nil
	}); err != nil {
		return err
	}

	//
	return nil
}

func validateCniContainerInterface(intf current.Interface) error {

	var link netlink.Link
	var err error

	if intf.Name == "" {
		return fmt.Errorf("Container interface name missing in prevResult: %v", intf.Name)
	}
	link, err = netlink.LinkByName(intf.Name)
	if err != nil {
		return fmt.Errorf("Container Interface name in prevResult: %s not found", intf.Name)
	}
	if intf.Sandbox == "" {
		return fmt.Errorf("Error: Container interface %s should not be in host namespace", link.Attrs().Name)
	}

	if intf.Mac != "" {
		if intf.Mac != link.Attrs().HardwareAddr.String() {
			return fmt.Errorf("Interface %s Mac %s doesn't match container Mac: %s", intf.Name, intf.Mac, link.Attrs().HardwareAddr)
		}
	}

	return nil
}
