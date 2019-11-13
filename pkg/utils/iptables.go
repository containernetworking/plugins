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
	"errors"
	"fmt"

	"github.com/coreos/go-iptables/iptables"
)

const statusChainExists = 1

// EnsureChain idempotently creates the iptables chain. It does not
// return an error if the chain already exists.
func EnsureChain(ipt *iptables.IPTables, table, chain string) error {
	if ipt == nil {
		return errors.New("failed to ensure iptable chain: IPTables was nil")
	}
	exists, err := ChainExists(ipt, table, chain)
	if err != nil {
		return fmt.Errorf("failed to list iptables chains: %v", err)
	}
	if !exists {
		err = ipt.NewChain(table, chain)
		if err != nil {
			eerr, eok := err.(*iptables.Error)
			if eok && eerr.ExitStatus() != statusChainExists {
				return err
			}
		}
	}
	return nil
}

// ChainExists checks whether an iptables chain exists.
func ChainExists(ipt *iptables.IPTables, table, chain string) (bool, error) {
	if ipt == nil {
		return false, errors.New("failed to check iptable chain: IPTables was nil")
	}
	chains, err := ipt.ListChains(table)
	if err != nil {
		return false, err
	}

	for _, ch := range chains {
		if ch == chain {
			return true, nil
		}
	}
	return false, nil
}
