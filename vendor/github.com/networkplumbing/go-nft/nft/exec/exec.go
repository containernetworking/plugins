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

package exec

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"

	nftconfig "github.com/networkplumbing/go-nft/nft/config"
)

const (
	cmdBin     = "nft"
	cmdHandle  = "-a"
	cmdEcho    = "-e"
	cmdFile    = "-f"
	cmdJSON    = "-j"
	cmdList    = "list"
	cmdRuleset = "ruleset"
	cmdStdin   = "-"
)

// ReadConfig loads the nftables configuration from the system and
// returns it as a nftables config structure.
// The system is expected to have the `nft` executable deployed and nftables enabled in the kernel.
func ReadConfig(ctx context.Context, filterCommands ...string) (*nftconfig.Config, error) {
	whatToList := cmdRuleset
	if len(filterCommands) > 0 {
		whatToList = strings.Join(filterCommands, " ")
	}
	stdout, err := execCommand(ctx, nil, cmdJSON, cmdList, whatToList)
	if err != nil {
		return nil, err
	}

	config := nftconfig.New()
	if err := config.FromJSON(stdout.Bytes()); err != nil {
		return nil, fmt.Errorf("failed to list ruleset: %v", err)
	}

	return config, nil
}

// ApplyConfig applies the given nftables config on the system.
// The system is expected to have the `nft` executable deployed and nftables enabled in the kernel.
func ApplyConfig(ctx context.Context, c *nftconfig.Config) error {
	data, err := c.ToJSON()
	if err != nil {
		return err
	}

	if _, err := execCommand(ctx, data, cmdJSON, cmdFile, cmdStdin); err != nil {
		return err
	}

	return nil
}

// ApplyConfigEcho applies the given nftables config on the system, echoing
// back the added elements with their assigned handles
// The system is expected to have the `nft` executable deployed and nftables enabled in the kernel.
func ApplyConfigEcho(ctx context.Context, c *nftconfig.Config) (*nftconfig.Config, error) {
	data, err := c.ToJSON()
	if err != nil {
		return nil, err
	}

	stdout, err := execCommand(ctx, data, cmdHandle, cmdEcho, cmdJSON, cmdFile, cmdStdin)
	if err != nil {
		return nil, err
	}

	config := nftconfig.New()
	if err := config.FromJSON(stdout.Bytes()); err != nil {
		return nil, fmt.Errorf("failed to parse echo: %v", err)
	}

	return config, nil
}

func execCommand(ctx context.Context, input []byte, args ...string) (*bytes.Buffer, error) {
	cmd := exec.CommandContext(ctx, cmdBin, args...)

	var stdout, stderr bytes.Buffer
	cmd.Stderr = &stderr
	cmd.Stdout = &stdout

	if input != nil {
		var stdin bytes.Buffer
		stdin.Write(input)
		cmd.Stdin = &stdin
	}

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf(
			"failed to execute %s %s: %v stdin:'%s' stdout:'%s' stderr:'%s'",
			cmd.Path, strings.Join(cmd.Args, " "), err, string(input), stdout.String(), stderr.String(),
		)
	}

	return &stdout, nil
}
