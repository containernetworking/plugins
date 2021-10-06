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
	"github.com/networkplumbing/go-nft/nft/schema"
)

// AddTable appends the given table to the nftable config.
// The table is added without an explicit action (`add`).
// Adding multiple times the same table has no effect when the config is applied.
func (c *Config) AddTable(table *schema.Table) {
	nftable := schema.Nftable{Table: table}
	c.Nftables = append(c.Nftables, nftable)
}

// DeleteTable appends a given table to the nftable config
// with the `delete` action.
// Attempting to delete a non-existing table, results with a failure when the config is applied.
// All chains and rules under the table are removed as well (when applied).
func (c *Config) DeleteTable(table *schema.Table) {
	nftable := schema.Nftable{Delete: &schema.Objects{Table: table}}
	c.Nftables = append(c.Nftables, nftable)
}

// FlushTable appends a given table to the nftable config
// with the `flush` action.
// All chains and rules under the table are removed (when applied).
// Attempting to flush a non-existing table, results with a failure when the config is applied.
func (c *Config) FlushTable(table *schema.Table) {
	nftable := schema.Nftable{Flush: &schema.Objects{Table: table}}
	c.Nftables = append(c.Nftables, nftable)
}

// LookupTable searches the configuration for a matching table and returns it.
// Mutating the returned table will result in mutating the configuration.
func (c *Config) LookupTable(toFind *schema.Table) *schema.Table {
	for _, nftable := range c.Nftables {
		if t := nftable.Table; t != nil {
			if t.Name == toFind.Name && t.Family == toFind.Family {
				return t
			}
		}
	}
	return nil
}
