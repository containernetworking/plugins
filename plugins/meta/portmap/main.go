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
	"log"
	"net"

	"golang.org/x/sys/unix"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	current "github.com/containernetworking/cni/pkg/types/100"
	"github.com/containernetworking/cni/pkg/version"
	"github.com/containernetworking/plugins/pkg/utils"
	bv "github.com/containernetworking/plugins/pkg/utils/buildversion"
)

type PortMapper interface {
	forwardPorts(config *PortMapConf, containerNet net.IPNet) error
	checkPorts(config *PortMapConf, containerNet net.IPNet) error
	unforwardPorts(config *PortMapConf) error
}

// These are vars rather than consts so we can "&" them
var (
	iptablesBackend = "iptables"
	nftablesBackend = "nftables"
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

	mapper PortMapper

	// Generic config
	Backend       *string   `json:"backend,omitempty"`
	SNAT          *bool     `json:"snat,omitempty"`
	ConditionsV4  *[]string `json:"conditionsV4"`
	ConditionsV6  *[]string `json:"conditionsV6"`
	MasqAll       bool      `json:"masqAll,omitempty"`
	MarkMasqBit   *int      `json:"markMasqBit"`
	RuntimeConfig struct {
		PortMaps []PortMapEntry `json:"portMappings,omitempty"`
	} `json:"runtimeConfig,omitempty"`

	// iptables-backend-specific config
	ExternalSetMarkChain *string `json:"externalSetMarkChain"`

	// These are fields parsed out of the config or the environment;
	// included here for convenience
	ContainerID string    `json:"-"`
	ContIPv4    net.IPNet `json:"-"`
	ContIPv6    net.IPNet `json:"-"`
}

// The default mark bit to signal that masquerading is required
// Kubernetes uses 14 and 15, Calico uses 20-31.
const DefaultMarkBit = 13

func cmdAdd(args *skel.CmdArgs) error {
	netConf, _, err := parseConfig(args.StdinData, args.IfName)
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

	if netConf.ContIPv4.IP != nil {
		if err := netConf.mapper.forwardPorts(netConf, netConf.ContIPv4); err != nil {
			return err
		}
		// Delete conntrack entries for UDP to avoid conntrack blackholing traffic
		// due to stale connections. We do that after the iptables rules are set, so
		// the new traffic uses them. Failures are informative only.
		if err := deletePortmapStaleConnections(netConf.RuntimeConfig.PortMaps, unix.AF_INET); err != nil {
			log.Printf("failed to delete stale UDP conntrack entries for %s: %v", netConf.ContIPv4.IP, err)
		}

		if *netConf.SNAT {
			// Set the route_localnet bit on the host interface, so that
			// 127/8 can cross a routing boundary.
			hostIfName := getRoutableHostIF(netConf.ContIPv4.IP)
			if hostIfName != "" {
				if err := enableLocalnetRouting(hostIfName); err != nil {
					return fmt.Errorf("unable to enable route_localnet: %v", err)
				}
			}
		}
	}

	if netConf.ContIPv6.IP != nil {
		if err := netConf.mapper.forwardPorts(netConf, netConf.ContIPv6); err != nil {
			return err
		}
		// Delete conntrack entries for UDP to avoid conntrack blackholing traffic
		// due to stale connections. We do that after the iptables rules are set, so
		// the new traffic uses them. Failures are informative only.
		if err := deletePortmapStaleConnections(netConf.RuntimeConfig.PortMaps, unix.AF_INET6); err != nil {
			log.Printf("failed to delete stale UDP conntrack entries for %s: %v", netConf.ContIPv6.IP, err)
		}
	}

	// Pass through the previous result
	return types.PrintResult(netConf.PrevResult, netConf.CNIVersion)
}

func cmdDel(args *skel.CmdArgs) error {
	netConf, _, err := parseConfig(args.StdinData, args.IfName)
	if err != nil {
		return fmt.Errorf("failed to parse config: %v", err)
	}

	if len(netConf.RuntimeConfig.PortMaps) == 0 {
		return nil
	}

	netConf.ContainerID = args.ContainerID

	// We don't need to parse out whether or not we're using v6 or snat,
	// deletion is idempotent
	return netConf.mapper.unforwardPorts(netConf)
}

func main() {
	skel.PluginMain(cmdAdd, cmdCheck, cmdDel, version.All, bv.BuildString("portmap"))
}

func cmdCheck(args *skel.CmdArgs) error {
	conf, result, err := parseConfig(args.StdinData, args.IfName)
	if err != nil {
		return err
	}

	// Ensure we have previous result.
	if result == nil {
		return fmt.Errorf("Required prevResult missing")
	}

	if len(conf.RuntimeConfig.PortMaps) == 0 {
		return nil
	}

	conf.ContainerID = args.ContainerID

	if conf.ContIPv4.IP != nil {
		if err := conf.mapper.checkPorts(conf, conf.ContIPv4); err != nil {
			return err
		}
	}

	if conf.ContIPv6.IP != nil {
		if err := conf.mapper.checkPorts(conf, conf.ContIPv6); err != nil {
			return err
		}
	}

	return nil
}

// parseConfig parses the supplied configuration (and prevResult) from stdin.
func parseConfig(stdin []byte, ifName string) (*PortMapConf, *current.Result, error) {
	conf := PortMapConf{}

	if err := json.Unmarshal(stdin, &conf); err != nil {
		return nil, nil, fmt.Errorf("failed to parse network configuration: %v", err)
	}

	// Parse previous result.
	var result *current.Result
	if conf.RawPrevResult != nil {
		var err error
		if err = version.ParsePrevResult(&conf.NetConf); err != nil {
			return nil, nil, fmt.Errorf("could not parse prevResult: %v", err)
		}

		result, err = current.NewResultFromResult(conf.PrevResult)
		if err != nil {
			return nil, nil, fmt.Errorf("could not convert result to current version: %v", err)
		}
	}

	conf.mapper = &portMapperIPTables{}

	if conf.SNAT == nil {
		tvar := true
		conf.SNAT = &tvar
	}

	if conf.MarkMasqBit != nil && conf.ExternalSetMarkChain != nil {
		return nil, nil, fmt.Errorf("Cannot specify externalSetMarkChain and markMasqBit")
	}

	if conf.MarkMasqBit == nil {
		bvar := DefaultMarkBit // go constants are "special"
		conf.MarkMasqBit = &bvar
	}

	if *conf.MarkMasqBit < 0 || *conf.MarkMasqBit > 31 {
		return nil, nil, fmt.Errorf("MasqMarkBit must be between 0 and 31")
	}

	err := validateBackend(&conf)
	if err != nil {
		return nil, nil, err
	}
	switch *conf.Backend {
	case iptablesBackend:
		conf.mapper = &portMapperIPTables{}

	case nftablesBackend:
		conf.mapper = &portMapperNFTables{}

	default:
		return nil, nil, fmt.Errorf("unrecognized backend %q", *conf.Backend)
	}

	// Reject invalid port numbers
	for _, pm := range conf.RuntimeConfig.PortMaps {
		if pm.ContainerPort <= 0 {
			return nil, nil, fmt.Errorf("Invalid container port number: %d", pm.ContainerPort)
		}
		if pm.HostPort <= 0 {
			return nil, nil, fmt.Errorf("Invalid host port number: %d", pm.HostPort)
		}
	}

	if conf.PrevResult != nil {
		for _, ip := range result.IPs {
			isIPv4 := ip.Address.IP.To4() != nil
			if !isIPv4 && conf.ContIPv6.IP != nil {
				continue
			} else if isIPv4 && conf.ContIPv4.IP != nil {
				continue
			}

			// Skip known non-sandbox interfaces
			if ip.Interface != nil {
				intIdx := *ip.Interface
				if intIdx >= 0 &&
					intIdx < len(result.Interfaces) &&
					(result.Interfaces[intIdx].Name != ifName ||
						result.Interfaces[intIdx].Sandbox == "") {
					continue
				}
			}
			if ip.Address.IP.To4() != nil {
				conf.ContIPv4 = ip.Address
			} else {
				conf.ContIPv6 = ip.Address
			}
		}
	}

	return &conf, result, nil
}

// validateBackend validates and/or sets conf.Backend
func validateBackend(conf *PortMapConf) error {
	backendConfig := make(map[string][]string)

	if conf.ExternalSetMarkChain != nil {
		backendConfig[iptablesBackend] = append(backendConfig[iptablesBackend], "externalSetMarkChain")
	}
	if conditionsBackend := detectBackendOfConditions(conf.ConditionsV4); conditionsBackend != "" {
		backendConfig[conditionsBackend] = append(backendConfig[conditionsBackend], "conditionsV4")
	}
	if conditionsBackend := detectBackendOfConditions(conf.ConditionsV6); conditionsBackend != "" {
		backendConfig[conditionsBackend] = append(backendConfig[conditionsBackend], "conditionsV6")
	}

	// If backend wasn't requested explicitly, default to iptables, unless it is not
	// available (and nftables is). FIXME: flip this default at some point.
	if conf.Backend == nil {
		if !utils.SupportsIPTables() && utils.SupportsNFTables() {
			conf.Backend = &nftablesBackend
		} else {
			conf.Backend = &iptablesBackend
		}
	}

	// Make sure we dont have config for the wrong backend
	var wrongBackend string
	if *conf.Backend == iptablesBackend {
		wrongBackend = nftablesBackend
	} else {
		wrongBackend = iptablesBackend
	}
	if len(backendConfig[wrongBackend]) > 0 {
		return fmt.Errorf("%s backend was requested but configuration contains %s-specific options %v", *conf.Backend, wrongBackend, backendConfig[wrongBackend])
	}

	// OK
	return nil
}

// detectBackendOfConditions returns "iptables" if conditions contains iptables
// conditions, "nftables" if it contains nftables conditions, and "" if it is empty.
func detectBackendOfConditions(conditions *[]string) string {
	if conditions == nil || len(*conditions) == 0 || (*conditions)[0] == "" {
		return ""
	}

	// The first token of any iptables condition would start with a hyphen (e.g. "-d",
	// "--sport", "-m"). No nftables condition would start that way. (An nftables
	// condition might include a negative number, but not as the first token.)
	if (*conditions)[0][0] == '-' {
		return iptablesBackend
	}
	return nftablesBackend
}
