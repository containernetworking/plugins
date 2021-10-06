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

// Table Address Families
const (
	FamilyIP     = "ip"     // IPv4 address AddressFamily.
	FamilyIP6    = "ip6"    // IPv6 address AddressFamily.
	FamilyINET   = "inet"   // Internet (IPv4/IPv6) address AddressFamily.
	FamilyARP    = "arp"    // ARP address AddressFamily, handling IPv4 ARP packets.
	FamilyBridge = "bridge" // Bridge address AddressFamily, handling packets which traverse a bridge device.
	FamilyNETDEV = "netdev" // Netdev address AddressFamily, handling packets from ingress.
)

type Table struct {
	Family string `json:"family"`
	Name   string `json:"name"`
}
