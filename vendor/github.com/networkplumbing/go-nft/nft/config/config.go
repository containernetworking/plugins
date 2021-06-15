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
	"encoding/json"

	"github.com/networkplumbing/go-nft/nft/schema"
)

type Config struct {
	schema.Root
}

// New returns a new nftables config structure.
func New() *Config {
	c := &Config{}
	c.Nftables = []schema.Nftable{}
	return c
}

// ToJSON returns the JSON encoding of the nftables config.
func (c *Config) ToJSON() ([]byte, error) {
	return json.Marshal(*c)
}

// FromJSON decodes the provided JSON-encoded data and populates the nftables config.
func (c *Config) FromJSON(data []byte) error {
	if err := json.Unmarshal(data, c); err != nil {
		return err
	}
	return nil
}

// FlushRuleset adds a command to the nftables config that erases all the configuration when applied.
// It is commonly used as the first config instruction, followed by a declarative configuration.
// When used, any previous configuration is flushed away before adding the new one.
// Calling FlushRuleset updates the configuration and will take effect only
// when applied on the system.
func (c *Config) FlushRuleset() {
	c.Nftables = append(c.Nftables, schema.Nftable{Flush: &schema.Objects{Ruleset: true}})
}
