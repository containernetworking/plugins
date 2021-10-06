/*
 * This file is part of the go-nft project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Copyright 2021 Red Hat, Inc.
 *
 */

package config

import (
	"bytes"
	"encoding/json"

	"github.com/networkplumbing/go-nft/nft/schema"
)

// AddRule appends the given rule to the nftable config.
// The rule is added without an explicit action (`add`).
// Adding multiple times the same rule will result in multiple identical rules when applied.
func (c *Config) AddRule(rule *schema.Rule) {
	nftable := schema.Nftable{Rule: rule}
	c.Nftables = append(c.Nftables, nftable)
}

// DeleteRule appends a given rule to the nftable config
// with the `delete` action.
// A rule is identified by its handle ID and it must be present in the given rule.
// Attempting to delete a non-existing rule, results with a failure when the config is applied.
// A common usage is to use LookupRule() and then to pass the result to DeleteRule.
func (c *Config) DeleteRule(rule *schema.Rule) {
	nftable := schema.Nftable{Delete: &schema.Objects{Rule: rule}}
	c.Nftables = append(c.Nftables, nftable)
}

// LookupRule searches the configuration for a matching rule and returns it.
// The rule is matched first by the table and chain.
// Other matching fields are optional (nil or an empty string arguments imply no-matching).
// Mutating the returned chain will result in mutating the configuration.
func (c *Config) LookupRule(toFind *schema.Rule) []*schema.Rule {
	var rules []*schema.Rule

	for _, nftable := range c.Nftables {
		if r := nftable.Rule; r != nil {
			match := r.Table == toFind.Table && r.Family == toFind.Family && r.Chain == toFind.Chain
			if match {
				if h := toFind.Handle; h != nil {
					match = match && r.Handle != nil && *r.Handle == *h
				}
				if i := toFind.Index; i != nil {
					match = match && r.Index != nil && *r.Index == *i
				}
				if co := toFind.Comment; co != "" {
					match = match && r.Comment == co
				}
				if toFindStatements := toFind.Expr; toFindStatements != nil {
					if match = match && len(toFindStatements) == len(r.Expr); match {
						for i, toFindStatement := range toFindStatements {
							equal, err := areStatementsEqual(toFindStatement, r.Expr[i])
							match = match && err == nil && equal
						}
					}
				}
				if match {
					rules = append(rules, r)
				}
			}
		}
	}
	return rules
}

func areStatementsEqual(statementA, statementB schema.Statement) (bool, error) {
	statementARow, err := json.Marshal(statementA)
	if err != nil {
		return false, err
	}
	statementBRow, err := json.Marshal(statementB)
	if err != nil {
		return false, err
	}
	return bytes.Equal(statementARow, statementBRow), nil
}
