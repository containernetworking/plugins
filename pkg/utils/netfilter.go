// Copyright 2023 CNI authors
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
	"os/exec"

	"github.com/coreos/go-iptables/iptables"
	"sigs.k8s.io/knftables"
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
	// knftables.New() does sanity checks so we don't need any further test like in
	// the iptables case.
	_, err := knftables.New(knftables.IPv4Family, "supports_nftables_test")
	return err == nil
}

// HasNFTablesCommand reports whether the nft binary is available on PATH.
// Unlike SupportsNFTables, this does not open a netlink connection and therefore
// does not require CAP_NET_ADMIN.
func HasNFTablesCommand() bool {
	_, err := exec.LookPath("nft")
	return err == nil
}

// PreferNFTablesDefault is used when no netfilter backend was requested
// explicitly. Prefer iptables when it works; if iptables is unavailable, fall
// back to nftables when either a full knftables probe succeeds or the nft
// binary is present (probe can fail without CAP_NET_ADMIN even on nft-only
// systems).
func PreferNFTablesDefault() bool {
	if SupportsIPTables() {
		return false
	}
	return SupportsNFTables() || HasNFTablesCommand()
}
