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

package schema

import (
	"encoding/json"
)

type Root struct {
	Nftables []Nftable `json:"nftables"`
}

const ruleSetKey = "ruleset"

type Objects struct {
	Table   *Table `json:"table,omitempty"`
	Chain   *Chain `json:"chain,omitempty"`
	Rule    *Rule  `json:"rule,omitempty"`
	Ruleset bool   `json:"-"`
}

func (o Objects) MarshalJSON() ([]byte, error) {
	type _Objects Objects
	objects := _Objects(o)

	data, err := json.Marshal(objects)
	if err != nil {
		return nil, err
	}

	if o.Ruleset {
		// Convert to a dynamic structure
		var dynamicStructure map[string]json.RawMessage
		if err := json.Unmarshal(data, &dynamicStructure); err != nil {
			return nil, err
		}
		dynamicStructure[ruleSetKey] = nil
		data, err = json.Marshal(dynamicStructure)
		if err != nil {
			return nil, err
		}
	}

	return data, nil
}

type Nftable struct {
	Table *Table `json:"table,omitempty"`
	Chain *Chain `json:"chain,omitempty"`
	Rule  *Rule  `json:"rule,omitempty"`

	Add    *Objects `json:"add,omitempty"`
	Delete *Objects `json:"delete,omitempty"`
	Flush  *Objects `json:"flush,omitempty"`

	Metainfo *Metainfo `json:"metainfo,omitempty"`
}

type Metainfo struct {
	Version           string `json:"version"`
	ReleaseName       string `json:"release_name"`
	JsonSchemaVersion int    `json:"json_schema_version"`
}
