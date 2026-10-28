// Copyright 2025 CNI authors
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

//go:build linux

package main

import (
	"fmt"
	"net"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
)

const (
	mptcpPMGenlName = "mptcp_pm"
	mptcpPMGenlVer  = 1
)

// MPTCP path manager commands (from linux/mptcp_pm.h).
const (
	mptcpPMCmdAddAddr   = 1
	mptcpPMCmdDelAddr   = 2
	mptcpPMCmdGetAddr   = 3
	mptcpPMCmdSetLimits = 5
	mptcpPMCmdGetLimits = 6
)

// MPTCP path manager top-level attributes.
const (
	mptcpPMAttrAddr        = 1
	mptcpPMAttrRcvAddAddrs = 2
	mptcpPMAttrSubflows    = 3
)

// MPTCP path manager address attributes (nested inside mptcpPMAttrAddr).
const (
	mptcpPMAddrAttrFamily = 1
	mptcpPMAddrAttrID     = 2
	mptcpPMAddrAttrAddr4  = 3
	mptcpPMAddrAttrAddr6  = 4
	mptcpPMAddrAttrPort   = 5
	mptcpPMAddrAttrFlags  = 6
	mptcpPMAddrAttrIfIdx  = 7
)

// MPTCP endpoint flags.
const (
	mptcpPMAddrFlagSignal   = 0x01
	mptcpPMAddrFlagSubflow  = 0x02
	mptcpPMAddrFlagBackup   = 0x04
	mptcpPMAddrFlagFullmesh = 0x08
)

// mptcpEndpoint represents a parsed MPTCP endpoint.
type mptcpEndpoint struct {
	Family uint16
	ID     uint8
	Addr   net.IP
	Flags  uint32
	IfIdx  int32
}

// getMPTCPFamilyID resolves the mptcp_pm generic netlink family ID.
// Must be called inside the target network namespace.
func getMPTCPFamilyID() (int, error) {
	fam, err := netlink.GenlFamilyGet(mptcpPMGenlName)
	if err != nil {
		return -1, fmt.Errorf("MPTCP path manager not available: %v", err)
	}
	return int(fam.ID), nil
}

// addEndpoint adds an MPTCP endpoint for the given IP address.
// The endpoint ID is auto-assigned by the kernel (ID=0).
func addEndpoint(familyID int, ip net.IP, flags uint32, ifIndex int) error {
	req := nl.NewNetlinkRequest(familyID, unix.NLM_F_ACK)

	addrAttr := nl.NewRtAttr(unix.NLA_F_NESTED|mptcpPMAttrAddr, nil)

	if ip.To4() != nil {
		addrAttr.AddChild(nl.NewRtAttr(mptcpPMAddrAttrFamily, nl.Uint16Attr(unix.AF_INET)))
		addrAttr.AddChild(nl.NewRtAttr(mptcpPMAddrAttrAddr4, ip.To4()))
	} else {
		addrAttr.AddChild(nl.NewRtAttr(mptcpPMAddrAttrFamily, nl.Uint16Attr(unix.AF_INET6)))
		addrAttr.AddChild(nl.NewRtAttr(mptcpPMAddrAttrAddr6, ip.To16()))
	}

	addrAttr.AddChild(nl.NewRtAttr(mptcpPMAddrAttrID, nl.Uint8Attr(0)))
	addrAttr.AddChild(nl.NewRtAttr(mptcpPMAddrAttrFlags, nl.Uint32Attr(flags)))

	if ifIndex > 0 {
		addrAttr.AddChild(nl.NewRtAttr(mptcpPMAddrAttrIfIdx, nl.Uint32Attr(uint32(ifIndex))))
	}

	raw := []byte{mptcpPMCmdAddAddr, mptcpPMGenlVer, 0, 0}
	raw = append(raw, addrAttr.Serialize()...)
	req.AddRawData(raw)

	_, err := req.Execute(unix.NETLINK_GENERIC, 0)
	return err
}

// delEndpoint deletes an MPTCP endpoint by its ID and address.
func delEndpoint(familyID int, id uint8, ip net.IP) error {
	req := nl.NewNetlinkRequest(familyID, unix.NLM_F_ACK)

	addrAttr := nl.NewRtAttr(unix.NLA_F_NESTED|mptcpPMAttrAddr, nil)

	if ip.To4() != nil {
		addrAttr.AddChild(nl.NewRtAttr(mptcpPMAddrAttrFamily, nl.Uint16Attr(unix.AF_INET)))
		addrAttr.AddChild(nl.NewRtAttr(mptcpPMAddrAttrAddr4, ip.To4()))
	} else {
		addrAttr.AddChild(nl.NewRtAttr(mptcpPMAddrAttrFamily, nl.Uint16Attr(unix.AF_INET6)))
		addrAttr.AddChild(nl.NewRtAttr(mptcpPMAddrAttrAddr6, ip.To16()))
	}

	addrAttr.AddChild(nl.NewRtAttr(mptcpPMAddrAttrID, nl.Uint8Attr(id)))

	raw := []byte{mptcpPMCmdDelAddr, mptcpPMGenlVer, 0, 0}
	raw = append(raw, addrAttr.Serialize()...)
	req.AddRawData(raw)

	_, err := req.Execute(unix.NETLINK_GENERIC, 0)
	return err
}

// listEndpoints lists all MPTCP endpoints in the current namespace.
func listEndpoints(familyID int) ([]mptcpEndpoint, error) {
	req := nl.NewNetlinkRequest(familyID, unix.NLM_F_DUMP)

	raw := []byte{mptcpPMCmdGetAddr, mptcpPMGenlVer, 0, 0}
	req.AddRawData(raw)

	msgs, err := req.Execute(unix.NETLINK_GENERIC, 0)
	if err != nil {
		return nil, err
	}

	var endpoints []mptcpEndpoint
	for _, msg := range msgs {
		ep, err := deserializeEndpoint(msg)
		if err != nil {
			return nil, err
		}
		endpoints = append(endpoints, ep)
	}
	return endpoints, nil
}

// deserializeEndpoint parses a generic netlink response message into an mptcpEndpoint.
func deserializeEndpoint(msg []byte) (mptcpEndpoint, error) {
	ep := mptcpEndpoint{}

	if len(msg) < nl.SizeofGenlmsg {
		return ep, fmt.Errorf("message too short: %d bytes", len(msg))
	}

	for attr := range nl.ParseAttributes(msg[nl.SizeofGenlmsg:]) {
		if attr.Type&nl.NLA_TYPE_MASK != uint16(mptcpPMAttrAddr) {
			continue
		}
		for nested := range nl.ParseAttributes(attr.Value) {
			switch nested.Type & nl.NLA_TYPE_MASK {
			case mptcpPMAddrAttrFamily:
				ep.Family = nl.NativeEndian().Uint16(nested.Value)
			case mptcpPMAddrAttrID:
				ep.ID = nested.Value[0]
			case mptcpPMAddrAttrAddr4:
				ep.Addr = make(net.IP, net.IPv4len)
				copy(ep.Addr, nested.Value)
			case mptcpPMAddrAttrAddr6:
				ep.Addr = make(net.IP, net.IPv6len)
				copy(ep.Addr, nested.Value)
			case mptcpPMAddrAttrFlags:
				ep.Flags = nl.NativeEndian().Uint32(nested.Value)
			case mptcpPMAddrAttrIfIdx:
				ep.IfIdx = int32(nl.NativeEndian().Uint32(nested.Value))
			}
		}
	}
	return ep, nil
}

// setLimits configures the MPTCP path manager limits.
func setLimits(familyID int, subflows, addAddrAccepted uint32) error {
	req := nl.NewNetlinkRequest(familyID, unix.NLM_F_ACK)

	attrs := []*nl.RtAttr{
		nl.NewRtAttr(mptcpPMAttrRcvAddAddrs, nl.Uint32Attr(addAddrAccepted)),
		nl.NewRtAttr(mptcpPMAttrSubflows, nl.Uint32Attr(subflows)),
	}

	raw := []byte{mptcpPMCmdSetLimits, mptcpPMGenlVer, 0, 0}
	for _, a := range attrs {
		raw = append(raw, a.Serialize()...)
	}
	req.AddRawData(raw)

	_, err := req.Execute(unix.NETLINK_GENERIC, 0)
	return err
}

// getLimits retrieves the current MPTCP path manager limits.
func getLimits(familyID int) (subflows, addAddrAccepted uint32, err error) {
	req := nl.NewNetlinkRequest(familyID, 0)

	raw := []byte{mptcpPMCmdGetLimits, mptcpPMGenlVer, 0, 0}
	req.AddRawData(raw)

	msgs, err := req.Execute(unix.NETLINK_GENERIC, 0)
	if err != nil {
		return 0, 0, err
	}

	if len(msgs) < 1 {
		return 0, 0, fmt.Errorf("empty response from MPTCP_PM_CMD_GET_LIMITS")
	}

	for attr := range nl.ParseAttributes(msgs[0][nl.SizeofGenlmsg:]) {
		switch attr.Type & nl.NLA_TYPE_MASK {
		case uint16(mptcpPMAttrRcvAddAddrs):
			addAddrAccepted = nl.NativeEndian().Uint32(attr.Value)
		case uint16(mptcpPMAttrSubflows):
			subflows = nl.NativeEndian().Uint32(attr.Value)
		}
	}
	return subflows, addAddrAccepted, nil
}

// endpointFlags converts an EndpointConfig into a bitmask of MPTCP endpoint flags.
func endpointFlags(cfg *EndpointConfig) uint32 {
	var flags uint32
	if cfg.Signal {
		flags |= mptcpPMAddrFlagSignal
	}
	if cfg.Subflow {
		flags |= mptcpPMAddrFlagSubflow
	}
	if cfg.Backup {
		flags |= mptcpPMAddrFlagBackup
	}
	if cfg.Fullmesh {
		flags |= mptcpPMAddrFlagFullmesh
	}
	return flags
}
