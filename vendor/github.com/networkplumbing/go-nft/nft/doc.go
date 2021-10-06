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

// Package nft provides a GO API to nftables.
// Together with the schema package, it allows to build, read and apply
// nftables configuration on a supporting system.
//
// The schema structures are based on libnftables-json (https://www.mankier.com/5/libnftables-json)
// and implement a subset of them.
//
// To create a new configuration, use `NewConfig` followed by methods
// which populates the configuration with tables, chains and rules, accompanied
// to specific actions (add, delete, flush).
//
//   config := nft.NewConfig()
//   table := nft.NewTable("mytable", nft.FamilyIP)
//   config.AddTable(table)
//   chain := nft.NewRegularChain(table, "mychain")
//   config.AddChain(chain)
//   rule := nft.NewRule(table, chain, statements, nil, nil, "mycomment")
//
// To apply a configuration on the system, use the `ApplyConfig` function.
//   err := nft.ApplyConfig(config)
//
// To read the configuration from the system, use the `ReadConfig` function.
//   config, err := nft.ReadConfig()
//
// For full setup example, see the integration test: tests/config_test.go
//
// The nft package is dependent on the `nft` binary and the kernel nftables
// support.
package nft
