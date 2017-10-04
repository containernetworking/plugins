// Copyright 2017 CNI authors
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

package hns

import (
	"encoding/json"
	"github.com/containernetworking/cni/pkg/types"
	"strings"
)

// NetConf is the CNI spec
type NetConf struct {
	types.NetConf
	AdditionalArgs []policyArgument `json:"AdditionalArgs,omitempty"`
}

type policyArgument struct {
	Name  string
	Value map[string]interface{}
}

// MarshalPolicies converts the Endpoint policies in AdditionalArgs
// to HNS specific policies as Json raw bytes
func (n *NetConf) MarshalPolicies() []json.RawMessage {
	if n.AdditionalArgs == nil {
		n.AdditionalArgs = []policyArgument{}
	}

	var result []json.RawMessage
	for _, policyArg := range n.AdditionalArgs {
		if !strings.EqualFold(policyArg.Name, "EndpointPolicy") {
			continue
		}
		if data, err := json.Marshal(policyArg.Value); err == nil {
			result = append(result, data)
		}
	}

	return result
}

// ApplyOutboundNatPolicy applies NAT Policy in VFP using HNS
// Simultaneously an exception is added for the network that has to be Nat'd
func (n *NetConf) ApplyOutboundNatPolicy(nwToNat string) {
	if n.AdditionalArgs == nil {
		n.AdditionalArgs = []policyArgument{}
	}

	for _, policy := range n.AdditionalArgs {
		if !strings.EqualFold(policy.Name, "EndpointPolicy") {
			continue
		}

		pv := policy.Value
		if !hasKey(pv, "Type") {
			continue
		}

		if !strings.EqualFold(pv["Type"].(string), "OutBoundNAT") {
			continue
		}

		if !hasKey(pv, "ExceptionList") {
			// add the exception since there weren't any
			pv["ExceptionList"] = []interface{}{nwToNat}
			return
		}

		nets := pv["ExceptionList"].([]interface{})
		for _, net := range nets {
			if net.(string) == nwToNat {
				// found it - do nothing
				return
			}
		}

		// its not in the list of exceptions, add it and we're done
		pv["ExceptionList"] = append(nets, nwToNat)
		return
	}

	// didn't find the policy, add it
	natEntry := policyArgument{
		Name: "EndpointPolicy",
		Value: map[string]interface{}{
			"Type": "OutBoundNAT",
			"ExceptionList": []interface{}{
				nwToNat,
			},
		},
	}

	n.AdditionalArgs = append(n.AdditionalArgs, natEntry)
}

// ApplyDefaultPAPolicy is used to configure a endpoint PA policy in HNS
func (n *NetConf) ApplyDefaultPAPolicy(paAddress string) {
	if n.AdditionalArgs == nil {
		n.AdditionalArgs = []policyArgument{}
	}

	// if its already present, leave untouched
	for _, policy := range n.AdditionalArgs {
		if policy.Name == "EndpointPolicy" {
			if hasKey(policy.Value, "PA") {
				// found it, don't override
				return
			}
		}
	}

	// did not find, add it now
	paPolicyData := map[string]interface{}{
		"Type": "PA",
		"PA":   paAddress,
	}
	paPolicy := &policyArgument{
		Name:  "EndpointPolicy",
		Value: paPolicyData,
	}

	n.AdditionalArgs = append(n.AdditionalArgs, *paPolicy)

	return
}

func hasKey(m map[string]interface{}, k string) bool {
	_, ok := m[k]
	return ok
}
