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
		return fmt.Errorf("failed to list iptables chains: %w", err)
	}
	if !exists {
		err = ipt.NewChain(table, chain)
		if err != nil {
			var eerr *iptables.Error
			if errors.As(err, &eerr) && eerr.ExitStatus() != statusChainExists {
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

// DeleteRule idempotently delete the iptables rule in the specified table/chain.
// It does not return an error if the referring chain doesn't exist
func DeleteRule(ipt *iptables.IPTables, table, chain string, rulespec ...string) error {
	if ipt == nil {
		return errors.New("failed to ensure iptable chain: IPTables was nil")
	}
	if err := ipt.Delete(table, chain, rulespec...); err != nil {
		var eerr *iptables.Error
		if errors.As(err, &eerr) {
			if eerr.IsNotExist() {
				// swallow here, the chain was already deleted
				return nil
			} else if eerr.ExitStatus() == 2 {
				// swallow here, invalid command line parameter because the referring rule is missing
				return nil
			}
		}
		return fmt.Errorf("failed to delete referring rule %s %s: %w", table, chain, err)
	}
	return nil
}

// DeleteChain idempotently deletes the specified table/chain.
// It does not return an errors if the chain does not exist
func DeleteChain(ipt *iptables.IPTables, table, chain string) error {
	if ipt == nil {
		return errors.New("failed to ensure iptable chain: IPTables was nil")
	}

	err := ipt.DeleteChain(table, chain)
	var eerr *iptables.Error
	if errors.As(err, &eerr) && eerr.IsNotExist() {
		// swallow here, the chain was already deleted
		return nil
	}
	return err
}

// ClearChain idempotently clear the iptables rules in the specified table/chain.
// If the chain does not exist, a new one will be created
func ClearChain(ipt *iptables.IPTables, table, chain string) error {
	if ipt == nil {
		return errors.New("failed to ensure iptable chain: IPTables was nil")
	}
	err := ipt.ClearChain(table, chain)
	var eerr *iptables.Error
	if errors.As(err, &eerr) && eerr.IsNotExist() {
		// swallow here, the chain was already deleted
		return EnsureChain(ipt, table, chain)
	}
	return err
}

// InsertUnique will add a rule to a chain if it does not already exist.
// By default the rule is appended, unless prepend is true.
func InsertUnique(ipt *iptables.IPTables, table, chain string, prepend bool, rule []string) error {
	exists, err := ipt.Exists(table, chain, rule...)
	if err != nil {
		return err
	}
	if exists {
		return nil
	}

	if prepend {
		return ipt.Insert(table, chain, 1, rule...)
	} else {
		return ipt.Append(table, chain, rule...)
	}
}
