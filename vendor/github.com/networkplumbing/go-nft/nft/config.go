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
	"context"
	"time"

	nftconfig "github.com/networkplumbing/go-nft/nft/config"
	nftexec "github.com/networkplumbing/go-nft/nft/exec"
)

type Config = nftconfig.Config

const (
	defaultTimeout = 30 * time.Second
)

// NewConfig returns a new nftables config structure.
func NewConfig() *nftconfig.Config {
	return nftconfig.New()
}

// ReadConfig loads the nftables configuration from the system and
// returns it as a nftables config structure.
// The system is expected to have the `nft` executable deployed and nftables enabled in the kernel.
func ReadConfig(filterCommands ...string) (*Config, error) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()
	return ReadConfigContext(ctx, filterCommands...)
}

// ReadConfigContext loads the nftables configuration from the system and
// returns it as a nftables config structure.
// The system is expected to have the `nft` executable deployed and nftables enabled in the kernel.
func ReadConfigContext(ctx context.Context, filterCommands ...string) (*Config, error) {
	return nftexec.ReadConfig(ctx, filterCommands...)
}

// ApplyConfig applies the given nftables config on the system.
// The system is expected to have the `nft` executable deployed and nftables enabled in the kernel.
func ApplyConfig(c *Config) error {
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()
	return ApplyConfigContext(ctx, c)
}

// ApplyConfigContext applies the given nftables config on the system.
// The system is expected to have the `nft` executable deployed and nftables enabled in the kernel.
func ApplyConfigContext(ctx context.Context, c *Config) error {
	return nftexec.ApplyConfig(ctx, c)
}

// ApplyConfigEcho applies the given nftables config on the system, echoing
// back the added elements with their assigned handles
// The system is expected to have the `nft` executable deployed and nftables enabled in the kernel.
func ApplyConfigEcho(ctx context.Context, c *Config) (*Config, error) {
	return nftexec.ApplyConfigEcho(ctx, c)
}
