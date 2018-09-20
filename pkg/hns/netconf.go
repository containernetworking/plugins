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
	"strings"

	"bytes"
	"github.com/buger/jsonparser"
	"github.com/containernetworking/cni/pkg/types"
)

// NetConf is the CNI spec
type NetConf struct {
	types.NetConf

	Policies []policy `json:"policies,omitempty"`
}

type policy struct {
	Name  string          `json:"name"`
	Value json.RawMessage `json:"value"`
}

// MarshalPolicies converts the Endpoint policies in Policies
// to HNS specific policies as Json raw bytes
func (n *NetConf) MarshalPolicies() []json.RawMessage {
	if n.Policies == nil {
		n.Policies = make([]policy, 0)
	}

	result := make([]json.RawMessage, 0, len(n.Policies))
	for _, p := range n.Policies {
		if !strings.EqualFold(p.Name, "EndpointPolicy") {
			continue
		}

		result = append(result, p.Value)
	}

	return result
}

// ApplyOutboundNatPolicy applies NAT Policy in VFP using HNS
// Simultaneously an exception is added for the network that has to be Nat'd
func (n *NetConf) ApplyOutboundNatPolicy(nwToNat string) {
	if n.Policies == nil {
		n.Policies = make([]policy, 0)
	}

	nwToNatBytes := []byte(nwToNat)

	for i, p := range n.Policies {
		if !strings.EqualFold(p.Name, "EndpointPolicy") {
			continue
		}

		typeValue, err := jsonparser.GetUnsafeString(p.Value, "Type")
		if err != nil || len(typeValue) == 0 {
			continue
		}

		if !strings.EqualFold(typeValue, "OutBoundNAT") {
			continue
		}

		exceptionListValue, dt, _, _ := jsonparser.Get(p.Value, "ExceptionList")
		// OutBoundNAT must with ExceptionList, so don't need to judge jsonparser.NotExist
		if dt == jsonparser.Array {
			buf := bytes.Buffer{}
			buf.WriteString(`{"Type": "OutBoundNAT", "ExceptionList": [`)

			jsonparser.ArrayEach(exceptionListValue, func(value []byte, dataType jsonparser.ValueType, offset int, err error) {
				if dataType == jsonparser.String && len(value) != 0 {
					if bytes.Compare(value, nwToNatBytes) != 0 {
						buf.WriteByte('"')
						buf.Write(value)
						buf.WriteByte('"')
						buf.WriteByte(',')
					}
				}
			})

			buf.WriteString(`"` + nwToNat + `"]}`)

			n.Policies[i] = policy{
				Name:  "EndpointPolicy",
				Value: buf.Bytes(),
			}
		} else {
			n.Policies[i] = policy{
				Name:  "EndpointPolicy",
				Value: []byte(`{"Type": "OutBoundNAT", "ExceptionList": ["` + nwToNat + `"]}`),
			}
		}

		return
	}

	// didn't find the policyArg, add it
	n.Policies = append(n.Policies, policy{
		Name:  "EndpointPolicy",
		Value: []byte(`{"Type": "OutBoundNAT", "ExceptionList": ["` + nwToNat + `"]}`),
	})
}

// ApplyDefaultPAPolicy is used to configure a endpoint PA policy in HNS
func (n *NetConf) ApplyDefaultPAPolicy(paAddress string) {
	if n.Policies == nil {
		n.Policies = make([]policy, 0)
	}

	// if its already present, leave untouched
	for i, p := range n.Policies {
		if !strings.EqualFold(p.Name, "EndpointPolicy") {
			continue
		}

		paValue, dt, _, _ := jsonparser.Get(p.Value, "PA")
		if dt == jsonparser.NotExist {
			continue
		} else if dt == jsonparser.String && len(paValue) != 0 {
			// found it, don't override
			return
		}

		n.Policies[i] = policy{
			Name:  "EndpointPolicy",
			Value: []byte(`{"Type": "PA", "PA": "` + paAddress + `"}`),
		}
		return
	}

	// didn't find the policyArg, add it
	n.Policies = append(n.Policies, policy{
		Name:  "EndpointPolicy",
		Value: []byte(`{"Type": "PA", "PA": "` + paAddress + `"}`),
	})
}
