// Copyright 2020 CNI authors
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
	"math"

	"github.com/vishvananda/netlink"
)

// findVRF finds a VRF link with the provided name.
func findVRF(name string) (*netlink.Vrf, error) {
	link, err := netlink.LinkByName(name)
	if err != nil {
		return nil, err
	}
	vrf, ok := link.(*netlink.Vrf)
	if !ok {
		return nil, fmt.Errorf("Netlink %s is not a VRF", name)
	}
	return vrf, nil
}

// createVRF creates a new VRF and sets it up.
func createVRF(name string, tableID uint32) (*netlink.Vrf, error) {
	links, err := netlink.LinkList()
	if err != nil {
		return nil, fmt.Errorf("createVRF: Failed to find links %v", err)
	}

	if tableID == 0 {
		tableID, err = findFreeRoutingTableID(links)
		if err != nil {
			return nil, err
		}
	}

	vrf := &netlink.Vrf{
		LinkAttrs: netlink.LinkAttrs{
			Name: name,
		},
		Table: tableID,
	}

	err = netlink.LinkAdd(vrf)
	if err != nil {
		return nil, fmt.Errorf("could not add VRF %s: %v", name, err)
	}
	err = netlink.LinkSetUp(vrf)
	if err != nil {
		return nil, fmt.Errorf("could not set link up for VRF %s: %v", name, err)
	}

	return vrf, nil
}

// assignedInterfaces returns the list of interfaces associated to the given vrf.
func assignedInterfaces(vrf *netlink.Vrf) ([]netlink.Link, error) {
	links, err := netlink.LinkList()
	if err != nil {
		return nil, fmt.Errorf("getAssignedInterfaces: Failed to find links %v", err)
	}
	res := make([]netlink.Link, 0)
	for _, l := range links {
		if l.Attrs().MasterIndex == vrf.Index {
			res = append(res, l)
		}
	}
	return res, nil
}

// addInterface adds the given interface to the VRF
func addInterface(vrf *netlink.Vrf, intf string) error {
	i, err := netlink.LinkByName(intf)
	if err != nil {
		return fmt.Errorf("could not get link by name %s", intf)
	}

	if i.Attrs().MasterIndex != 0 {
		master, err := netlink.LinkByIndex(i.Attrs().MasterIndex)
		if err != nil {
			return fmt.Errorf("interface %s has already a master set, could not retrieve the name: %v", intf, err)
		}
		return fmt.Errorf("interface %s has already a master set: %s", intf, master.Attrs().Name)
	}

	// IPV6 addresses are not maintained unless
	// sysctl -w net.ipv6.conf.all.keep_addr_on_down=1 is called
	// so we save it, and restore it back.
	beforeAddresses, err := netlink.AddrList(i, netlink.FAMILY_V6)
	if err != nil {
		return fmt.Errorf("failed getting ipv6 addresses for %s", intf)
	}
	err = netlink.LinkSetMaster(i, vrf)
	if err != nil {
		return fmt.Errorf("could not set vrf %s as master of %s: %v", vrf.Name, intf, err)
	}

	afterAddresses, err := netlink.AddrList(i, netlink.FAMILY_V6)
	if err != nil {
		return fmt.Errorf("failed getting ipv6 new addresses for %s", intf)
	}

	// Since keeping the ipv6 address depends on net.ipv6.conf.all.keep_addr_on_down ,
	// we check if the new interface does not have them and in case we restore them.
CONTINUE:
	for _, toFind := range beforeAddresses {
		for _, current := range afterAddresses {
			if toFind.Equal(current) {
				continue CONTINUE
			}
		}
		// Not found, re-adding it
		err = netlink.AddrAdd(i, &toFind)
		if err != nil {
			return fmt.Errorf("could not restore address %s to %s @ %s: %v", toFind, intf, vrf.Name, err)
		}
	}

	return nil
}

func findFreeRoutingTableID(links []netlink.Link) (uint32, error) {
	takenTables := make(map[uint32]struct{}, len(links))
	for _, l := range links {
		if vrf, ok := l.(*netlink.Vrf); ok {
			takenTables[vrf.Table] = struct{}{}
		}
	}

	for res := uint32(1); res < math.MaxUint32; res++ {
		if _, ok := takenTables[res]; !ok {
			return res, nil
		}
	}
	return 0, fmt.Errorf("findFreeRoutingTableID: Failed to find an available routing id")
}

func resetMaster(interfaceName string) error {
	intf, err := netlink.LinkByName(interfaceName)
	if err != nil {
		return fmt.Errorf("resetMaster: could not get link by name %s", interfaceName)
	}
	err = netlink.LinkSetNoMaster(intf)
	if err != nil {
		return fmt.Errorf("resetMaster: could reset master to %s", interfaceName)
	}
	return nil
}
