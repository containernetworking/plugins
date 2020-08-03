// Copyright 2018 Google LLC. All Rights Reserved.
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
	"fmt"

	"github.com/google/nftables/binaryutil"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

type ExthdrOp uint32

const (
	ExthdrOpIpv6   ExthdrOp = unix.NFT_EXTHDR_OP_IPV6
	ExthdrOpTcpopt ExthdrOp = unix.NFT_EXTHDR_OP_TCPOPT
)

type Exthdr struct {
	DestRegister   uint32
	Type           uint8
	Offset         uint32
	Len            uint32
	Flags          uint32
	Op             ExthdrOp
	SourceRegister uint32
}

func (e *Exthdr) marshal() ([]byte, error) {
	data, err := netlink.MarshalAttributes([]netlink.Attribute{
		{Type: unix.NFTA_EXTHDR_SREG, Data: binaryutil.BigEndian.PutUint32(e.SourceRegister)},
		{Type: unix.NFTA_EXTHDR_TYPE, Data: []byte{e.Type}},
		{Type: unix.NFTA_EXTHDR_OFFSET, Data: binaryutil.BigEndian.PutUint32(e.Offset)},
		{Type: unix.NFTA_EXTHDR_LEN, Data: binaryutil.BigEndian.PutUint32(e.Len)},
		// TODO: these fields seem to be conditional?
		//{Type: unix.NFTA_EXTHDR_DREG, Data: binaryutil.BigEndian.PutUint32(e.DestRegister)},
		//{Type: unix.NFTA_EXTHDR_FLAGS, Data: binaryutil.BigEndian.PutUint32(e.Flags)},
		{Type: unix.NFTA_EXTHDR_OP, Data: binaryutil.BigEndian.PutUint32(uint32(e.Op))},
	})
	if err != nil {
		return nil, err
	}
	return netlink.MarshalAttributes([]netlink.Attribute{
		{Type: unix.NFTA_EXPR_NAME, Data: []byte("exthdr\x00")},
		{Type: unix.NLA_F_NESTED | unix.NFTA_EXPR_DATA, Data: data},
	})
}

func (e *Exthdr) unmarshal(data []byte) error {
	return fmt.Errorf("not yet implemented")
}
