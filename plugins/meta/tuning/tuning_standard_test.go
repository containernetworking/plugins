// Copyright 2026 CNI authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"sync"
	"testing"
)

// TestDynamicSysctlWithoutStaticSysctl verifies that dynamic args.cni.sysctl
// parameters are safely processed without a nil map assignment panic when
// static sysctl configuration is omitted.
func TestDynamicSysctlWithoutStaticSysctl(t *testing.T) {
	configJSON := []byte(`{
		"cniVersion": "1.0.0",
		"name": "tuning-dynamic-test",
		"type": "tuning",
		"args": {
			"cni": {
				"sysctl": {
					"net.ipv4.ip_forward": "1"
				}
			}
		}
	}`)

	// parseConf must initialize conf.SysCtl and copy dynamic keys without panicking
	conf, err := parseConf(configJSON, "")
	if err != nil {
		t.Fatalf("parseConf returned unexpected error: %v", err)
	}

	if conf.SysCtl == nil {
		t.Fatalf("expected conf.SysCtl to be initialized, got nil")
	}

	if conf.SysCtl["net.ipv4.ip_forward"] != "1" {
		t.Fatalf("expected dynamic sysctl to be set, got: %v", conf.SysCtl["net.ipv4.ip_forward"])
	}
}

// TestValidateSysctlCrossCallIsolation verifies that validateSysctlConflictingKeys
// does not leak state across sequential invocations in the same process.
func TestValidateSysctlCrossCallIsolation(t *testing.T) {
	validConfig := []byte(`{
		"sysctl": {
			"net.ipv4.conf.all.forwarding": "1"
		}
	}`)

	// First invocation
	if err := validateSysctlConflictingKeys(validConfig); err != nil {
		t.Fatalf("first validation should succeed, got: %v", err)
	}

	// Second invocation with identical valid configuration must also succeed
	if err := validateSysctlConflictingKeys(validConfig); err != nil {
		t.Fatalf("second validation should succeed without false duplicate error, got: %v", err)
	}
}

// TestValidateSysctlConflictingKeysConcurrent verifies that concurrent calls
// to validateSysctlConflictingKeys are thread-safe and free of data races.
func TestValidateSysctlConflictingKeysConcurrent(t *testing.T) {
	testJSON := []byte(`{
		"sysctl": {
			"net.ipv4.ip_forward": "1"
		}
	}`)

	var wg sync.WaitGroup
	numGoroutines := 20
	errChan := make(chan error, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := validateSysctlConflictingKeys(testJSON); err != nil {
				errChan <- err
			}
		}()
	}

	wg.Wait()
	close(errChan)

	for err := range errChan {
		t.Errorf("concurrent validation failed unexpectedly: %v", err)
	}
}
