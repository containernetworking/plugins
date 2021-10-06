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
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"strings"

	nftconfig "github.com/networkplumbing/go-nft/nft/config"
)

const (
	cmdBin     = "nft"
	cmdFile    = "-f"
	cmdJSON    = "-j"
	cmdList    = "list"
	cmdRuleset = "ruleset"
)

// ReadConfig loads the nftables configuration from the system and
// returns it as a nftables config structure.
// The system is expected to have the `nft` executable deployed and nftables enabled in the kernel.
func ReadConfig() (*nftconfig.Config, error) {
	stdout, err := execCommand(cmdJSON, cmdList, cmdRuleset)
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
func ApplyConfig(c *nftconfig.Config) error {
	data, err := c.ToJSON()
	if err != nil {
		return err
	}

	tmpFile, err := ioutil.TempFile(os.TempDir(), "spoofcheck-")
	if err != nil {
		return fmt.Errorf("failed to create temporary file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err = tmpFile.Write(data); err != nil {
		return fmt.Errorf("failed to write to temporary file: %v", err)
	}

	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("failed to close temporary file: %v", err)
	}

	if _, err := execCommand(cmdJSON, cmdFile, tmpFile.Name()); err != nil {
		return err
	}

	return nil
}

func execCommand(args ...string) (*bytes.Buffer, error) {
	cmd := exec.Command(cmdBin, args...)

	var stdout, stderr bytes.Buffer
	cmd.Stderr = &stderr
	cmd.Stdout = &stdout

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf(
			"failed to execute %s %s: %v stdout:'%s' stderr:'%s'",
			cmd.Path, strings.Join(cmd.Args, " "), err, stdout.String(), stderr.String(),
		)
	}

	return &stdout, nil
}
