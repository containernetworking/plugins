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
	sysBusPCI       = "/sys/bus/pci/devices"
	sysBusAuxiliary = "/sys/bus/auxiliary/devices"
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

	// for internal use
	auxDevice string `json:"-"` // Auxiliary device name as appears on Auxiliary bus (/sys/bus/auxiliary)
}

func init() {
	// this ensures that main runs only on main thread (thread group leader).
	// since namespace ops (unshare, setns) are done for a single thread, we
	// must ensure that the goroutine does not jump from OS thread to thread
	runtime.LockOSThread()
}

// handleDeviceID updates netconf fields with DeviceID runtime config
func handleDeviceID(netconf *NetConf) error {
	deviceID := netconf.RuntimeConfig.DeviceID
	if deviceID == "" {
		return nil
	}

	// Check if deviceID is a PCI device
	pciPath := filepath.Join(sysBusPCI, deviceID)
	if _, err := os.Stat(pciPath); err == nil {
		netconf.PCIAddr = deviceID
		return nil
	}

	// Check if deviceID is an Auxiliary device
	auxPath := filepath.Join(sysBusAuxiliary, deviceID)
	if _, err := os.Stat(auxPath); err == nil {
		netconf.PCIAddr = ""
		netconf.auxDevice = deviceID
		return nil
	}

	return fmt.Errorf("runtime config DeviceID %s not found or unsupported", deviceID)
}

func loadConf(bytes []byte) (*NetConf, error) {
	n := &NetConf{}
	var err error
	if err = json.Unmarshal(bytes, n); err != nil {
		return nil, fmt.Errorf("failed to load netconf: %v", err)
	}

	// Override device with the standardized DeviceID if provided in Runtime Config.
	if err := handleDeviceID(n); err != nil {
		return nil, err
	}

	if n.Device == "" && n.HWAddr == "" && n.KernelPath == "" && n.PCIAddr == "" && n.auxDevice == "" {
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
		hostDev, err := getLink(cfg.Device, cfg.HWAddr, cfg.KernelPath, cfg.PCIAddr, cfg.auxDevice)
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
			return ipam.ConfigureIface(args.IfName, newResult)
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

func moveLinkIn(hostDev netlink.Link, containerNs ns.NetNS, containerIfName string) (netlink.Link, error) {
	hostDevName := hostDev.Attrs().Name

	// With recent kernels we could do all changes in a single netlink call,
	// but on failure the device is left in a partially modified state.
	// Doing changes one by one allow us to (try to) rollback to the initial state.

	// Create a temporary namespace to rename (and modify) the device in.
	// We were previously using a temporary name, but rapid rename leads to
	// race condition with udev and NetworkManager.
	tempNS, err := ns.TempNetNS()
	if err != nil {
		return nil, fmt.Errorf("failed to create tempNS: %v", err)
	}
	defer tempNS.Close()

	// Restore original up state in case of error
	// This must be done in the hostNS as moving
	// device between namespaces sets the link down
	if hostDev.Attrs().Flags&net.FlagUp == net.FlagUp {
		defer func() {
			if err != nil {
				// lookup the device again (index might have changed)
				if hostDev, err := netlink.LinkByName(hostDevName); err == nil {
					_ = netlink.LinkSetUp(hostDev)
				}
			}
		}()
	}

	// Move the host device into tempNS
	if err = netlink.LinkSetNsFd(hostDev, int(tempNS.Fd())); err != nil {
		return nil, fmt.Errorf("failed to move %q to tempNS: %v", hostDevName, err)
	}

	var contDev netlink.Link

	// In a container in container scenario, hostNS is not the initial net namespace,
	// but host / container naming is easier to follow.
	if err = tempNS.Do(func(hostNS ns.NetNS) error {
		// lookup the device in tempNS (index might have changed)
		tempNSDev, err := netlink.LinkByName(hostDevName)
		if err != nil {
			return fmt.Errorf("failed to find %q in tempNS: %v", hostDevName, err)
		}

		// detroying a non empty tempNS would move physical devices back to the initial net namespace,
		// not the namespace of the "parent" process, and virtual devices would be destroyed,
		// so we need to actively move the device back to hostNS on error
		defer func() {
			if err != nil && tempNSDev != nil {
				_ = netlink.LinkSetNsFd(tempNSDev, int(hostNS.Fd()))
			}
		}()

		// Rename the device to the wanted name
		if err = netlink.LinkSetName(tempNSDev, containerIfName); err != nil {
			return fmt.Errorf("failed to rename host device %q to %q: %v", hostDevName, containerIfName, err)
		}

		// Restore the original device name in case of error
		defer func() {
			if err != nil && tempNSDev != nil {
				_ = netlink.LinkSetName(tempNSDev, hostDevName)
			}
		}()

		// Save host device name into the container device's alias property
		if err = netlink.LinkSetAlias(tempNSDev, hostDevName); err != nil {
			return fmt.Errorf("failed to set alias to %q: %v", hostDevName, err)
		}

		// Remove the alias on error
		defer func() {
			if err != nil && tempNSDev != nil {
				_ = netlink.LinkSetAlias(tempNSDev, "")
			}
		}()

		// Move the device to the containerNS
		if err = netlink.LinkSetNsFd(tempNSDev, int(containerNs.Fd())); err != nil {
			return fmt.Errorf("failed to move %q (host: %q) to container NS: %v", containerIfName, hostDevName, err)
		}

		// Lookup the device again on error, the index might have changed
		defer func() {
			if err != nil {
				tempNSDev, _ = netlink.LinkByName(containerIfName)
			}
		}()

		err = containerNs.Do(func(_ ns.NetNS) error {
			var err error
			contDev, err = netlink.LinkByName(containerIfName)
			if err != nil {
				return fmt.Errorf("failed to find %q in container NS: %v", containerIfName, err)
			}

			// Move the interface back to tempNS on error
			defer func() {
				if err != nil {
					_ = netlink.LinkSetNsFd(contDev, int(tempNS.Fd()))
				}
			}()

			// Bring the device up
			// This must be done in the containerNS
			if err = netlink.LinkSetUp(contDev); err != nil {
				return fmt.Errorf("failed to set %q up: %v", containerIfName, err)
			}

			return nil
		})

		return err
	}); err != nil {
		return nil, err
	}

	return contDev, nil
}

func moveLinkOut(containerNs ns.NetNS, containerIfName string) error {
	// Create a temporary namespace to rename (and modify) the device in.
	// We were previously using a temporary name, but multiple rapid renames
	// leads to race condition with udev and NetworkManager.
	tempNS, err := ns.TempNetNS()
	if err != nil {
		return fmt.Errorf("failed to create tempNS: %v", err)
	}
	defer tempNS.Close()

	var contDev netlink.Link

	// Restore original up state in case of error
	// This must be done in the containerNS as moving
	// device between namespaces sets the link down
	defer func() {
		if err != nil && contDev != nil && contDev.Attrs().Flags&net.FlagUp == net.FlagUp {
			containerNs.Do(func(_ ns.NetNS) error {
				// lookup the device again (index might have changed)
				if contDev, err := netlink.LinkByName(containerIfName); err == nil {
					_ = netlink.LinkSetUp(contDev)
				}
				return nil
			})
		}
	}()

	err = containerNs.Do(func(_ ns.NetNS) error {
		var err error
		// Lookup the device in the containerNS
		contDev, err = netlink.LinkByName(containerIfName)
		if err != nil {
			return fmt.Errorf("failed to find %q in containerNS: %v", containerIfName, err)
		}

		// Verify we have the original name
		if contDev.Attrs().Alias == "" {
			return fmt.Errorf("failed to find original ifname for %q (alias is not set)", containerIfName)
		}

		// Move the device to the tempNS
		if err = netlink.LinkSetNsFd(contDev, int(tempNS.Fd())); err != nil {
			return fmt.Errorf("failed to move %q to tempNS: %v", containerIfName, err)
		}
		return nil
	})
	if err != nil {
		return err
	}

	err = tempNS.Do(func(hostNS ns.NetNS) error {
		// Lookup the device in tempNS (index might have changed)
		tempNSDev, err := netlink.LinkByName(containerIfName)
		if err != nil {
			return fmt.Errorf("failed to find %q in tempNS: %v", containerIfName, err)
		}

		// Move the device back to containerNS on error
		defer func() {
			if err != nil {
				_ = netlink.LinkSetNsFd(tempNSDev, int(containerNs.Fd()))
			}
		}()

		hostDevName := tempNSDev.Attrs().Alias

		// Rename container device to hostDevName
		if err = netlink.LinkSetName(tempNSDev, hostDevName); err != nil {
			return fmt.Errorf("failed to rename device %q to %q: %v", containerIfName, hostDevName, err)
		}

		// Rename the device back to containerIfName on error
		defer func() {
			if err != nil {
				_ = netlink.LinkSetName(tempNSDev, containerIfName)
			}
		}()

		// Unset device's alias property
		if err = netlink.LinkSetAlias(tempNSDev, ""); err != nil {
			return fmt.Errorf("failed to unset alias of %q: %v", hostDevName, err)
		}

		// Set back the device alias to hostDevName on error
		defer func() {
			if err != nil {
				_ = netlink.LinkSetAlias(tempNSDev, hostDevName)
			}
		}()

		// Finally move the device to the hostNS
		if err = netlink.LinkSetNsFd(tempNSDev, int(hostNS.Fd())); err != nil {
			return fmt.Errorf("failed to move %q to hostNS: %v", hostDevName, err)
		}

		// As we don't know the previous state, leave the link down

		return nil
	})
	if err != nil {
		return err
	}

	return nil
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

func linkFromPath(path string) (netlink.Link, error) {
	entries, err := os.ReadDir(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read directory %s: %q", path, err)
	}
	if len(entries) > 0 {
		// grab the first net device
		return netlink.LinkByName(entries[0].Name())
	}
	return nil, fmt.Errorf("failed to find network device in path %s", path)
}

func getLink(devname, hwaddr, kernelpath, pciaddr string, auxDev string) (netlink.Link, error) {
	switch {

	case len(devname) > 0:
		return netlink.LinkByName(devname)
	case len(hwaddr) > 0:
		hwAddr, err := net.ParseMAC(hwaddr)
		if err != nil {
			return nil, fmt.Errorf("failed to parse MAC address %q: %v", hwaddr, err)
		}

		links, err := netlink.LinkList()
		if err != nil {
			return nil, fmt.Errorf("failed to list node links: %v", err)
		}

		for _, link := range links {
			if bytes.Equal(link.Attrs().HardwareAddr, hwAddr) {
				return link, nil
			}
		}
	case len(kernelpath) > 0:
		if !filepath.IsAbs(kernelpath) || !strings.HasPrefix(kernelpath, "/sys/devices/") {
			return nil, fmt.Errorf("kernel device path %q must be absolute and begin with /sys/devices/", kernelpath)
		}
		netDir := filepath.Join(kernelpath, "net")
		return linkFromPath(netDir)
	case len(pciaddr) > 0:
		netDir := filepath.Join(sysBusPCI, pciaddr, "net")
		if _, err := os.Lstat(netDir); err != nil {
			virtioNetDir := filepath.Join(sysBusPCI, pciaddr, "virtio*", "net")
			matches, err := filepath.Glob(virtioNetDir)
			if matches == nil || err != nil {
				return nil, fmt.Errorf("no net directory under pci device %s", pciaddr)
			}
			netDir = matches[0]
		}
		return linkFromPath(netDir)
	case len(auxDev) > 0:
		netDir := filepath.Join(sysBusAuxiliary, auxDev, "net")
		return linkFromPath(netDir)
	}

	return nil, fmt.Errorf("failed to find physical interface")
}

func main() {
	skel.PluginMainFuncs(skel.CNIFuncs{
		Add:    cmdAdd,
		Check:  cmdCheck,
		Del:    cmdDel,
		Status: cmdStatus,
		/* FIXME GC */
	}, version.All, bv.BuildString("host-device"))
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

func cmdStatus(args *skel.CmdArgs) error {
	conf := NetConf{}
	if err := json.Unmarshal(args.StdinData, &conf); err != nil {
		return fmt.Errorf("failed to load netconf: %w", err)
	}

	if conf.IPAM.Type != "" {
		if err := ipam.ExecStatus(conf.IPAM.Type, args.StdinData); err != nil {
			return err
		}
	}

	// TODO: Check if host device exists.

	return nil
}
