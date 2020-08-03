// Copyright 2020 Google LLC. All Rights Reserved.
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

package expr

import (
	"encoding/binary"
	"time"

	"github.com/google/nftables/binaryutil"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// Dynset represent a rule dynamically adding or updating a set or a map based on an incoming packet.
type Dynset struct {
	SrcRegKey  uint32
	SrcRegData uint32
	SetID      uint32
	SetName    string
	Operation  uint32
	Timeout    time.Duration
	Invert     bool
}

func (e *Dynset) marshal() ([]byte, error) {
	// See: https://git.netfilter.org/libnftnl/tree/src/expr/dynset.c
	var opAttrs []netlink.Attribute
	opAttrs = append(opAttrs, netlink.Attribute{Type: unix.NFTA_DYNSET_SREG_KEY, Data: binaryutil.BigEndian.PutUint32(e.SrcRegKey)})
	if e.SrcRegData != 0 {
		opAttrs = append(opAttrs, netlink.Attribute{Type: unix.NFTA_DYNSET_SREG_DATA, Data: binaryutil.BigEndian.PutUint32(e.SrcRegData)})
	}
	opAttrs = append(opAttrs, netlink.Attribute{Type: unix.NFTA_DYNSET_OP, Data: binaryutil.BigEndian.PutUint32(e.Operation)})
	if e.Timeout != 0 {
		opAttrs = append(opAttrs, netlink.Attribute{Type: unix.NFTA_DYNSET_TIMEOUT, Data: binaryutil.BigEndian.PutUint64(uint64(e.Timeout.Milliseconds()))})
	}
	if e.Invert {
		opAttrs = append(opAttrs, netlink.Attribute{Type: unix.NFTA_DYNSET_FLAGS, Data: binaryutil.BigEndian.PutUint32(unix.NFT_DYNSET_F_INV)})
	}
	opAttrs = append(opAttrs,
		netlink.Attribute{Type: unix.NFTA_DYNSET_SET_NAME, Data: []byte(e.SetName + "\x00")},
		netlink.Attribute{Type: unix.NFTA_DYNSET_SET_ID, Data: binaryutil.BigEndian.PutUint32(e.SetID)})
	opData, err := netlink.MarshalAttributes(opAttrs)
	if err != nil {
		return nil, err
	}

	return netlink.MarshalAttributes([]netlink.Attribute{
		{Type: unix.NFTA_EXPR_NAME, Data: []byte("dynset\x00")},
		{Type: unix.NLA_F_NESTED | unix.NFTA_EXPR_DATA, Data: opData},
	})
}

func (e *Dynset) unmarshal(data []byte) error {
	ad, err := netlink.NewAttributeDecoder(data)
	if err != nil {
		return err
	}
	ad.ByteOrder = binary.BigEndian
	for ad.Next() {
		switch ad.Type() {
		case unix.NFTA_DYNSET_SET_NAME:
			e.SetName = ad.String()
		case unix.NFTA_DYNSET_SET_ID:
			e.SetID = ad.Uint32()
		case unix.NFTA_DYNSET_SREG_KEY:
			e.SrcRegKey = ad.Uint32()
		case unix.NFTA_DYNSET_SREG_DATA:
			e.SrcRegData = ad.Uint32()
		case unix.NFTA_DYNSET_OP:
			e.Operation = ad.Uint32()
		case unix.NFTA_DYNSET_TIMEOUT:
			e.Timeout = time.Duration(time.Millisecond * time.Duration(ad.Uint64()))
		case unix.NFTA_DYNSET_FLAGS:
			e.Invert = (ad.Uint32() & unix.NFT_DYNSET_F_INV) != 0
		}
	}
	return ad.Err()
}
