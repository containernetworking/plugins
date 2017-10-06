// Copyright 2015 CNI authors
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
	"github.com/stretchr/testify/assert"
	"net"
	"testing"
)

func TestFlannelSetsWindowsOutboundNatWhenNotSet(t *testing.T) {
	// given a subnet config that requests ipmasq
	_, nw, _ := net.ParseCIDR("192.168.0.0/16")
	_, sn, _ := net.ParseCIDR("192.168.10.0/24")
	ipmasq := true
	fenv := &subnetEnv{
		nw:     nw,
		sn:     sn,
		ipmasq: &ipmasq,
	}

	// apply it
	delegate := make(map[string]interface{})
	updateOutboundNat(&delegate, fenv)

	// verify it got applied
	assert.True(t, hasKey(delegate, "AdditionalArgs"))

	addlArgs := (delegate["AdditionalArgs"]).([]interface{})
	assert.Equal(t, 1, len(addlArgs))

	policy := addlArgs[0].(map[string]interface{})
	assert.True(t, hasKey(policy, "Name"))
	assert.True(t, hasKey(policy, "Value"))
	assert.Equal(t, "EndpointPolicy", policy["Name"])

	value := policy["Value"].(map[string]interface{})
	assert.True(t, hasKey(value, "Type"))
	assert.True(t, hasKey(value, "ExceptionList"))
	assert.Equal(t, "OutBoundNAT", value["Type"])

	exceptionList := value["ExceptionList"].([]interface{})
	assert.Equal(t, 1, len(exceptionList))
	assert.Equal(t, nw.String(), exceptionList[0].(string))
}

func TestFlannelAppendsOutboundNatToExistingPolicy(t *testing.T) {

	// given a subnet config that requests ipmasq
	_, nw, _ := net.ParseCIDR("192.168.0.0/16")
	_, sn, _ := net.ParseCIDR("192.168.10.0/24")
	ipmasq := true
	fenv := &subnetEnv{
		nw:     nw,
		sn:     sn,
		ipmasq: &ipmasq,
	}

	// first set it
	delegate := make(map[string]interface{})
	updateOutboundNat(&delegate, fenv)

	// then attempt to update it
	_, nw2, _ := net.ParseCIDR("10.244.0.0/16")
	fenv.nw = nw2
	updateOutboundNat(&delegate, fenv)

	// but it stays the same!
	addlArgs := (delegate["AdditionalArgs"]).([]interface{})
	policy := addlArgs[0].(map[string]interface{})
	value := policy["Value"].(map[string]interface{})
	exceptionList := value["ExceptionList"].([]interface{})
	assert.Equal(t, nw.String(), exceptionList[0].(string))
	assert.Equal(t, nw2.String(), exceptionList[1].(string))
}
