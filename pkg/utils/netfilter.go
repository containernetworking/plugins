// Copyright 2017 CNI authors
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

package utils

import (
	"github.com/coreos/go-iptables/iptables"
	"github.com/danwinship/nftables"
)

// SupportsIPTables tests whether the system supports using netfilter via the iptables API
// (whether via "iptables-legacy" or "iptables-nft"). (Note that this returns true if it
// is *possible* to use iptables; it does not test whether any other components on the
// system are *actually* using iptables.)
func SupportsIPTables() bool {
	ipt, err := iptables.NewWithProtocol(iptables.ProtocolIPv4)
	if err != nil {
		return false
	}
	// We don't care whether the chain actually exists, only whether we can *check*
	// whether it exists.
	_, err = ipt.ChainExists("filter", "INPUT")
	return err == nil
}

// SupportsNFTables tests whether the system supports using netfilter via the nftables API
// (ie, not via "iptables-nft"). (Note that this returns true if it is *possible* to use
// nftables; it does not test whether any other components on the system are *actually*
// using nftables.)
func SupportsNFTables() bool {
	nft := nftables.New(nftables.IPv4Family, "supports_nftables_test")
	err := nft.Present()
	return err == nil
}
