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

package nft

import (
	"github.com/networkplumbing/go-nft/nft/schema"
)

// NewRule returns a new schema rule structure.
func NewRule(table *schema.Table, chain *schema.Chain, expr []schema.Statement, handle *int, index *int, comment string) *schema.Rule {
	c := &schema.Rule{
		Family:  table.Family,
		Table:   table.Name,
		Chain:   chain.Name,
		Expr:    expr,
		Handle:  handle,
		Index:   index,
		Comment: comment,
	}

	return c
}

type RuleIndex int

// NewRuleIndex returns a rule index object which acts as an iterator.
// When multiple rules are added to a chain, index allows to define an order between them.
// The first rule which is added to a chain should have no index (it is assigned index 0),
// following rules should have the index set, referencing after/before which rule the new one is to be added/inserted.
func NewRuleIndex() *RuleIndex {
	var index RuleIndex = -1
	return &index
}

// Next returns the next iteration value as an integer pointer.
// When first time called, it returns the value 0.
func (i *RuleIndex) Next() *int {
	*i++
	var index = int(*i)
	return &index
}
