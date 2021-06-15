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

type ChainType string
type ChainHook string
type ChainPolicy string

// Chain Types
const (
	TypeFilter ChainType = schema.TypeFilter
	TypeNAT    ChainType = schema.TypeNAT
	TypeRoute  ChainType = schema.TypeRoute
)

// Chain Hooks
const (
	HookPreRouting  ChainHook = schema.HookPreRouting
	HookInput       ChainHook = schema.HookInput
	HookOutput      ChainHook = schema.HookOutput
	HookForward     ChainHook = schema.HookForward
	HookPostRouting ChainHook = schema.HookPostRouting
	HookIngress     ChainHook = schema.HookIngress
)

// Chain Policies
const (
	PolicyAccept ChainPolicy = schema.PolicyAccept
	PolicyDrop   ChainPolicy = schema.PolicyDrop
)

// NewRegularChain returns a new schema chain structure for a regular chain.
func NewRegularChain(table *schema.Table, name string) *schema.Chain {
	return NewChain(table, name, nil, nil, nil, nil)
}

// NewChain returns a new schema chain structure for a base chain.
// For base chains, all arguments are required except the policy.
// Missing arguments will cause an error once the config is applied.
func NewChain(table *schema.Table, name string, ctype *ChainType, hook *ChainHook, prio *int, policy *ChainPolicy) *schema.Chain {
	c := &schema.Chain{
		Family: table.Family,
		Table:  table.Name,
		Name:   name,
	}

	if ctype != nil {
		c.Type = string(*ctype)
	}
	if hook != nil {
		c.Hook = string(*hook)
	}
	if prio != nil {
		c.Prio = prio
	}
	if policy != nil {
		c.Policy = string(*policy)
	}

	return c
}
