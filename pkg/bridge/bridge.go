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

package bridge

import (
	"fmt"
	"strings"
	"syscall"

	"github.com/containernetworking/plugins/pkg/bridge/ebtables"
	utilexec "github.com/containernetworking/plugins/pkg/exec"
)

const (
	dedupChain  = "CNI-DEDUP"
	filterTable = "filter"
	outputChain = "OUTPUT"
)

// AddDedupRules adds two ebtables rules providing the following:
// 1) Allow the bridge IP address when using the src bridge mac
// 2) Block any other IP in the network sourced with the bridge interface's mac
//    address.
// For example if the bridge address is 192.16.1.1/24 the following ebtables
// rules will be setup.
//  -t filter -A CNI-DEDUP -p IPv4 -s <bridge-mac> -o veth+ --ip-src 192.168.1.1 -j ACCEPT
//  -t filter -A CNI-DEDUP -p IPv4 -s <bridge-mac> -o veth+ --ip-src 192.168.1.0/24 -j DROP
func AddDedupRules(mac, ip, nw string, family uint16) error {
	ebt, err := ebtables.New(utilexec.New())
	if err != nil {
		return err
	}
	if err := ebt.NewChain(filterTable, dedupChain); err != nil {
		// Make chain creation idempotent.
		if !strings.Contains(err.Error(), "already exists") {
			return err
		}
	}

	var common_args []string
	switch family {
	case syscall.AF_INET:
		common_args = []string{"-p", "IPv4", "-s", mac, "-o", "veth+", "--ip-src"}
	case syscall.AF_INET6:
		common_args = []string{"-p", "IPv6", "-s", mac, "-o", "veth+", "--ip6-src"}
	default:
		return fmt.Errorf("unsupported protocol family %q", family)
	}

	if err := ebt.AppendUnique(filterTable, dedupChain, append(common_args, ip, "-j", "ACCEPT")...); err != nil {
		return err
	}
	if err := ebt.AppendUnique(filterTable, dedupChain, append(common_args, nw, "-j", "DROP")...); err != nil {
		return err
	}

	if err := ebt.AppendUnique(filterTable, outputChain, "-j", dedupChain); err != nil {
		return err
	}

	return nil

}

// DeleteDedupRules delets all ebtables rules under the "CNI-DEDUP" chain
// including the chain.
func DeleteDedupRules() error {
	ebt, err := ebtables.New(utilexec.New())
	if err != nil {
		return err
	}
	if err := ebt.Delete(filterTable, outputChain, "-j", dedupChain); err != nil {
		// Make rule deletion idempotent.
		if strings.Contains(err.Error(), "Illegal target name") {
			return nil
		}
		return err
	}
	if err := ebt.DeleteChain(filterTable, dedupChain); err != nil {
		// Make chain deletion idempotent.
		if strings.Contains(err.Error(), "Illegal target name") {
			return nil
		}
		return err
	}

	return nil
}
