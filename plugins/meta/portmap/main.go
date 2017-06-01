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

// This is a post-setup plugin that establishes port forwarding - using iptables,
// from the host's network interface(s) to a pod's network interface.
//
// It is intended to be used as a chained CNI plugin, and determines the container
// IP from the previous result. If the result includes an IPv6 address, it will
// also be configured. (IPTables will not forward cross-family).
//
// This has one notable limitation: it does not perform any kind of reservation
// of the actual host port. If there is a service on the host, it will have all
// its traffic captured by the container. If another container also claims a given
// port, it will caputure the traffic - it is last-write-wins.
package main

import (
	"encoding/json"
	"fmt"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/cni/pkg/types/current"
	"github.com/containernetworking/cni/pkg/version"
)

// PortMapEntry corresponds to a single entry in the port_mappings argument,
// see CONVENTIONS.md
type PortMapEntry struct {
	HostPort      int    `json:"hostPort"`
	ContainerPort int    `json:"containerPort"`
	Protocol      string `json:"protocol"`
	HostIP        string `json:"hostIP,omitempty"`
}

type PortMapConf struct {
	types.NetConf
	SNAT          *bool     `json:"snat,omitempty"`
	ConditionsV4  *[]string `json:"conditionsV4"`
	ConditionsV6  *[]string `json:"conditionsV6"`
	RuntimeConfig struct {
		PortMaps []PortMapEntry `json:"portMappings,omitempty"`
	} `json:"runtimeConfig,omitempty"`
	RawPrevResult map[string]interface{} `json:"prevResult,omitempty"`
	PrevResult    *current.Result        `json:"-"`
	ContainerID   string
}

func cmdAdd(args *skel.CmdArgs) error {
	netConf, err := parseConfig(args.StdinData)
	if err != nil {
		return fmt.Errorf("failed to parse config: %v", err)
	}

	if netConf.PrevResult == nil {
		return fmt.Errorf("must be called as chained plugin")
	}

	if len(netConf.RuntimeConfig.PortMaps) == 0 {
		return types.PrintResult(netConf.PrevResult, netConf.CNIVersion)
	}

	netConf.ContainerID = args.ContainerID

	// Loop through IPs, setting up forwarding to the first container IP
	// per family
	hasV4 := false
	hasV6 := false
	for _, ip := range netConf.PrevResult.IPs {
		if ip.Version == "6" && hasV6 {
			continue
		} else if ip.Version == "4" && hasV4 {
			continue
		}

		// Skip known non-sandbox interfaces
		intIdx := ip.Interface
		if intIdx >= 0 && intIdx < len(netConf.PrevResult.Interfaces) && netConf.PrevResult.Interfaces[intIdx].Name != args.IfName {
			continue
		}

		if err := forwardPorts(netConf, ip.Address.IP); err != nil {
			return err
		}

		if ip.Version == "6" {
			hasV6 = true
		} else {
			hasV4 = true
		}
	}

	// Pass through the previous result
	return types.PrintResult(netConf.PrevResult, netConf.CNIVersion)
}

func cmdDel(args *skel.CmdArgs) error {
	netConf, err := parseConfig(args.StdinData)
	if err != nil {
		return fmt.Errorf("failed to parse config: %v", err)
	}

	netConf.ContainerID = args.ContainerID

	// We don't need to parse out whether or not we're using v6 or snat,
	// deletion is idempotent
	if err := unforwardPorts(netConf); err != nil {
		return err
	}
	return nil
}

func main() {
	skel.PluginMain(cmdAdd, cmdDel, version.PluginSupports("", "0.1.0", "0.2.0", "0.3.0", version.Current()))
}

// parseConfig parses the supplied configuration (and prevResult) from stdin.
func parseConfig(stdin []byte) (*PortMapConf, error) {
	conf := PortMapConf{}

	if err := json.Unmarshal(stdin, &conf); err != nil {
		return nil, fmt.Errorf("failed to parse network configuration: %v", err)
	}

	// Parse previous result.
	if conf.RawPrevResult != nil {
		resultBytes, err := json.Marshal(conf.RawPrevResult)
		if err != nil {
			return nil, fmt.Errorf("could not serialize prevResult: %v", err)
		}
		res, err := version.NewResult(conf.CNIVersion, resultBytes)
		if err != nil {
			return nil, fmt.Errorf("could not parse prevResult: %v", err)
		}
		conf.RawPrevResult = nil
		conf.PrevResult, err = current.NewResultFromResult(res)
		if err != nil {
			return nil, fmt.Errorf("could not convert result to current version: %v", err)
		}
	}

	if conf.SNAT == nil {
		tvar := true
		conf.SNAT = &tvar
	}

	return &conf, nil
}
