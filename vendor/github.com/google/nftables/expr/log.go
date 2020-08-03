// Copyright 2019 Google LLC. All Rights Reserved.
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

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// Log defines type for NFT logging
type Log struct {
	Key  uint32
	Data []byte
}

func (e *Log) marshal() ([]byte, error) {
	var data []byte
	var err error
	switch e.Key {
	case unix.NFTA_LOG_GROUP:
		data, err = netlink.MarshalAttributes([]netlink.Attribute{
			{Type: unix.NFTA_LOG_GROUP, Data: e.Data},
		})
	case unix.NFTA_LOG_PREFIX:
		prefix := append(e.Data, '\x00')
		data, err = netlink.MarshalAttributes([]netlink.Attribute{
			{Type: unix.NFTA_LOG_PREFIX, Data: prefix},
		})
	case unix.NFTA_LOG_SNAPLEN:
		data, err = netlink.MarshalAttributes([]netlink.Attribute{
			{Type: unix.NFTA_LOG_SNAPLEN, Data: e.Data},
		})
	case unix.NFTA_LOG_QTHRESHOLD:
		data, err = netlink.MarshalAttributes([]netlink.Attribute{
			{Type: unix.NFTA_LOG_QTHRESHOLD, Data: e.Data},
		})
	case unix.NFTA_LOG_LEVEL:
		level := append(e.Data, '\x00')
		data, err = netlink.MarshalAttributes([]netlink.Attribute{
			{Type: unix.NFTA_LOG_LEVEL, Data: level},
		})
	}
	if err != nil {
		return nil, err
	}

	return netlink.MarshalAttributes([]netlink.Attribute{
		{Type: unix.NFTA_EXPR_NAME, Data: []byte("log\x00")},
		{Type: unix.NLA_F_NESTED | unix.NFTA_EXPR_DATA, Data: data},
	})
}

func (e *Log) unmarshal(data []byte) error {
	ad, err := netlink.NewAttributeDecoder(data)
	if err != nil {
		return err
	}

	ad.ByteOrder = binary.BigEndian
	if ad.Next() {
		e.Key = uint32(ad.Type())
		e.Data = ad.Bytes()
		switch e.Key {
		case unix.NFTA_LOG_PREFIX:
			fallthrough
		case unix.NFTA_LOG_LEVEL:
			// Getting rid of \x00 at the end of string
			e.Data = e.Data[:len(e.Data)-1]
		}
	}
	return ad.Err()
}
