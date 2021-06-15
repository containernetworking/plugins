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

// Chain Types
const (
	TypeFilter = "filter"
	TypeNAT    = "nat"
	TypeRoute  = "route"
)

// Chain Hooks
const (
	HookPreRouting  = "prerouting"
	HookInput       = "input"
	HookOutput      = "output"
	HookForward     = "forward"
	HookPostRouting = "postrouting"
	HookIngress     = "ingress"
)

// Chain Policies
const (
	PolicyAccept = "accept"
	PolicyDrop   = "drop"
)

type Chain struct {
	Family string `json:"family"`
	Table  string `json:"table"`
	Name   string `json:"name"`
	Type   string `json:"type,omitempty"`
	Hook   string `json:"hook,omitempty"`
	Prio   *int   `json:"prio,omitempty"`
	Policy string `json:"policy,omitempty"`
}
