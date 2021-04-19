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
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/Microsoft/hcsshim/hcn"
	"github.com/buger/jsonparser"
	"github.com/containernetworking/cni/pkg/types"
)

// NetConf is the CNI spec
type NetConf struct {
	types.NetConf
	// ApiVersion specifies the policies type of HNS or HCN, select one of [1, 2].
	// HNS is the v1 API, which is the default version and applies to dockershim.
	// HCN is the v2 API, which can leverage HostComputeNamespace and use in containerd.
	ApiVersion int `json:"apiVersion,omitempty"`
	// Policies specifies the policy list for HNSEndpoint or HostComputeEndpoint.
	Policies []Policy `json:"policies,omitempty"`
	// RuntimeConfig represents the options to be passed in by the runtime.
	RuntimeConfig RuntimeConfig `json:"runtimeConfig"`
	// LoopbackDSR specifies whether to support loopback direct server return.
	LoopbackDSR bool `json:"loopbackDSR,omitempty"`
}

type RuntimeDNS struct {
	Nameservers []string `json:"servers,omitempty"`
	Search      []string `json:"searches,omitempty"`
}

type PortMapEntry struct {
	HostPort      int    `json:"hostPort"`
	ContainerPort int    `json:"containerPort"`
	Protocol      string `json:"protocol"`
	HostIP        string `json:"hostIP,omitempty"`
}

// constants of the supported Windows Socket protocol,
// ref to https://docs.microsoft.com/en-us/dotnet/api/system.net.sockets.protocoltype.
var protocolEnums = map[string]uint32{
	"icmpv4": 1,
	"igmp":   2,
	"tcp":    6,
	"udp":    17,
	"icmpv6": 58,
}

func (p *PortMapEntry) GetProtocolEnum() (uint32, error) {
	var u, err = strconv.ParseUint(p.Protocol, 0, 10)
	if err != nil {
		var pe, exist = protocolEnums[strings.ToLower(p.Protocol)]
		if !exist {
			return 0, errors.New("invalid protocol supplied to port mapping policy")
		}
		return pe, nil
	}
	return uint32(u), nil
}

type RuntimeConfig struct {
	DNS      RuntimeDNS     `json:"dns"`
	PortMaps []PortMapEntry `json:"portMappings,omitempty"`
}

type Policy struct {
	Name  string          `json:"name"`
	Value json.RawMessage `json:"value"`
}

// GetHNSEndpointPolicies converts the configuration policies to HNSEndpoint policies.
func (n *NetConf) GetHNSEndpointPolicies() []json.RawMessage {
	result := make([]json.RawMessage, 0, len(n.Policies))
	for _, p := range n.Policies {
		if !strings.EqualFold(p.Name, "EndpointPolicy") {
			continue
		}
		result = append(result, p.Value)
	}
	return result
}

// GetHostComputeEndpointPolicies converts the configuration policies to HostComputeEndpoint policies.
func (n *NetConf) GetHostComputeEndpointPolicies() []hcn.EndpointPolicy {
	result := make([]hcn.EndpointPolicy, 0, len(n.Policies))
	for _, p := range n.Policies {
		if !strings.EqualFold(p.Name, "EndpointPolicy") {
			continue
		}
		var policy hcn.EndpointPolicy
		if err := json.Unmarshal(p.Value, &policy); err != nil {
			continue
		}
		result = append(result, policy)
	}
	return result
}

// GetDNS returns the DNS values if they are there use that else use netconf supplied DNS.
func (n *NetConf) GetDNS() types.DNS {
	dnsResult := n.DNS
	if len(n.RuntimeConfig.DNS.Nameservers) > 0 {
		dnsResult.Nameservers = n.RuntimeConfig.DNS.Nameservers
	}
	if len(n.RuntimeConfig.DNS.Search) > 0 {
		dnsResult.Search = n.RuntimeConfig.DNS.Search
	}
	return dnsResult
}

// ApplyLoopbackDSRPolicy configures the given IP to support loopback DSR.
func (n *NetConf) ApplyLoopbackDSRPolicy(ip *net.IP) {
	if err := hcn.DSRSupported(); err != nil || ip == nil {
		return
	}

	toPolicyValue := func(addr string) json.RawMessage {
		if n.ApiVersion == 2 {
			return bprintf(`{"Type": "OutBoundNAT", "Settings": {"Destinations": ["%s"]}}`, addr)
		}
		return bprintf(`{"Type": "OutBoundNAT", "Destinations": ["%s"]}`, addr)
	}
	ipBytes := []byte(ip.String())

	// find OutBoundNAT policy
	for i := range n.Policies {
		p := &n.Policies[i]
		if !strings.EqualFold(p.Name, "EndpointPolicy") {
			continue
		}

		// filter OutBoundNAT policy
		typeValue, _ := jsonparser.GetUnsafeString(p.Value, "Type")
		if typeValue != "OutBoundNAT" {
			continue
		}

		// parse destination address list
		var (
			destinationsValue []byte
			dt                jsonparser.ValueType
		)
		if n.ApiVersion == 2 {
			destinationsValue, dt, _, _ = jsonparser.Get(p.Value, "Settings", "Destinations")
		} else {
			destinationsValue, dt, _, _ = jsonparser.Get(p.Value, "Destinations")
		}

		// skip if Destinations/DestinationList field is not found
		if dt == jsonparser.NotExist {
			continue
		}

		// return if found the given address
		if dt == jsonparser.Array {
			var found bool
			_, _ = jsonparser.ArrayEach(destinationsValue, func(value []byte, dataType jsonparser.ValueType, offset int, err error) {
				if dataType == jsonparser.String && len(value) != 0 {
					if bytes.Compare(value, ipBytes) == 0 {
						found = true
					}
				}
			})
			if found {
				return
			}
		}
	}

	// or add a new OutBoundNAT if not found
	n.Policies = append(n.Policies, Policy{
		Name:  "EndpointPolicy",
		Value: toPolicyValue(ip.String()),
	})
}

// ApplyOutboundNatPolicy applies the sNAT policy in HNS/HCN and configures the given CIDR as an exception.
func (n *NetConf) ApplyOutboundNatPolicy(exceptionCIDR string) {
	if exceptionCIDR == "" {
		return
	}

	toPolicyValue := func(cidr ...string) json.RawMessage {
		if n.ApiVersion == 2 {
			return bprintf(`{"Type": "OutBoundNAT", "Settings": {"Exceptions": ["%s"]}}`, strings.Join(cidr, `","`))
		}
		return bprintf(`{"Type": "OutBoundNAT", "ExceptionList": ["%s"]}`, strings.Join(cidr, `","`))
	}
	exceptionCIDRBytes := []byte(exceptionCIDR)

	// find OutBoundNAT policy
	for i := range n.Policies {
		p := &n.Policies[i]
		if !strings.EqualFold(p.Name, "EndpointPolicy") {
			continue
		}

		// filter OutBoundNAT policy
		typeValue, _ := jsonparser.GetUnsafeString(p.Value, "Type")
		if typeValue != "OutBoundNAT" {
			continue
		}

		// parse exception CIDR list
		var (
			exceptionsValue []byte
			dt              jsonparser.ValueType
		)
		if n.ApiVersion == 2 {
			exceptionsValue, dt, _, _ = jsonparser.Get(p.Value, "Settings", "Exceptions")
		} else {
			exceptionsValue, dt, _, _ = jsonparser.Get(p.Value, "ExceptionList")
		}

		// skip if Exceptions/ExceptionList field is not found
		if dt == jsonparser.NotExist {
			continue
		}

		// return if found the given CIDR
		if dt == jsonparser.Array {
			var found bool
			_, _ = jsonparser.ArrayEach(exceptionsValue, func(value []byte, dataType jsonparser.ValueType, offset int, err error) {
				if dataType == jsonparser.String && len(value) != 0 {
					if bytes.Compare(value, exceptionCIDRBytes) == 0 {
						found = true
					}
				}
			})
			if found {
				return
			}
		}
	}

	// or add a new OutBoundNAT if not found
	n.Policies = append(n.Policies, Policy{
		Name:  "EndpointPolicy",
		Value: toPolicyValue(exceptionCIDR),
	})
}

// ApplyDefaultPAPolicy applies an endpoint PA policy in HNS/HCN.
func (n *NetConf) ApplyDefaultPAPolicy(address string) {
	if address == "" {
		return
	}

	toPolicyValue := func(addr string) json.RawMessage {
		if n.ApiVersion == 2 {
			return bprintf(`{"Type": "ProviderAddress", "Settings": {"ProviderAddress": "%s"}}`, addr)
		}
		return bprintf(`{"Type": "PA", "PA": "%s"}`, addr)
	}
	addressBytes := []byte(address)

	// find ProviderAddress policy
	for i := range n.Policies {
		p := &n.Policies[i]
		if !strings.EqualFold(p.Name, "EndpointPolicy") {
			continue
		}

		// filter ProviderAddress policy
		typeValue, _ := jsonparser.GetUnsafeString(p.Value, "Type")
		if typeValue != "PA" && typeValue != "ProviderAddress" {
			continue
		}

		// parse provider address
		var (
			paValue []byte
			dt      jsonparser.ValueType
		)
		if n.ApiVersion == 2 {
			paValue, dt, _, _ = jsonparser.Get(p.Value, "Settings", "ProviderAddress")
		} else {
			paValue, dt, _, _ = jsonparser.Get(p.Value, "PA")
		}

		// skip if ProviderAddress/PA field is not found
		if dt == jsonparser.NotExist {
			continue
		}

		// return if found the given address
		if dt == jsonparser.String && bytes.Compare(paValue, addressBytes) == 0 {
			return
		}
	}

	// or add a new ProviderAddress if not found
	n.Policies = append(n.Policies, Policy{
		Name:  "EndpointPolicy",
		Value: toPolicyValue(address),
	})
}

// ApplyPortMappingPolicy applies the host/container port mapping policies in HNS/HCN.
func (n *NetConf) ApplyPortMappingPolicy(portMappings []PortMapEntry) {
	if len(portMappings) == 0 {
		return
	}

	toPolicyValue := func(p *PortMapEntry) json.RawMessage {
		if n.ApiVersion == 2 {
			var protocolEnum, _ = p.GetProtocolEnum()
			return bprintf(`{"Type": "PortMapping", "Settings": {"InternalPort": %d, "ExternalPort": %d, "Protocol": %d, "VIP": "%s"}}`, p.ContainerPort, p.HostPort, protocolEnum, p.HostIP)
		}
		return bprintf(`{"Type": "NAT", "InternalPort": %d, "ExternalPort": %d, "Protocol": "%s"}`, p.ContainerPort, p.HostPort, p.Protocol)
	}

	for i := range portMappings {
		p := &portMappings[i]
		// skip the invalid protocol mapping
		if _, err := p.GetProtocolEnum(); err != nil {
			continue
		}
		n.Policies = append(n.Policies, Policy{
			Name:  "EndpointPolicy",
			Value: toPolicyValue(p),
		})
	}
}

// bprintf is similar to fmt.Sprintf and returns a byte array as result.
func bprintf(format string, a ...interface{}) []byte {
	return []byte(fmt.Sprintf(format, a...))
}
