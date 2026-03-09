// Copyright 2025 CNI authors
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

// This is a "meta-plugin". It reads in its own netconf, it does not create
// any network interface but configures MPTCP endpoints and limits.

package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	current "github.com/containernetworking/cni/pkg/types/100"
	"github.com/containernetworking/cni/pkg/version"
	"github.com/containernetworking/plugins/pkg/netlinksafe"
	"github.com/containernetworking/plugins/pkg/ns"
	bv "github.com/containernetworking/plugins/pkg/utils/buildversion"
)

// EndpointConfig specifies the flags for MPTCP endpoints.
type EndpointConfig struct {
	Signal   bool `json:"signal"`
	Subflow  bool `json:"subflow"`
	Backup   bool `json:"backup"`
	Fullmesh bool `json:"fullmesh"`
}

// LimitsConfig specifies the MPTCP path manager limits.
// Nil fields are left unchanged from their current values.
type LimitsConfig struct {
	Subflows        *uint32 `json:"subflows,omitempty"`
	AddAddrAccepted *uint32 `json:"addAddrAccepted,omitempty"`
}

// MPTCPNetConf represents the MPTCP plugin configuration.
type MPTCPNetConf struct {
	types.NetConf

	Endpoints *EndpointConfig `json:"endpoints,omitempty"`
	Limits    *LimitsConfig   `json:"limits,omitempty"`
}

func main() {
	skel.PluginMainFuncs(skel.CNIFuncs{
		Add:   cmdAdd,
		Check: cmdCheck,
		Del:   cmdDel,
	}, version.VersionsStartingFrom("0.3.1"), bv.BuildString("mptcp"))
}

func cmdAdd(args *skel.CmdArgs) error {
	conf, result, err := parseConf(args.StdinData)
	if err != nil {
		return err
	}

	if conf.PrevResult == nil {
		return fmt.Errorf("missing prevResult from earlier plugin")
	}

	err = ns.WithNetNSPath(args.Netns, func(_ ns.NetNS) error {
		familyID, err := getMPTCPFamilyID()
		if err != nil {
			return err
		}

		if conf.Endpoints != nil {
			link, err := netlinksafe.LinkByName(args.IfName)
			if err != nil {
				return fmt.Errorf("failed to look up interface %q: %v", args.IfName, err)
			}
			ifIndex := link.Attrs().Index

			flags := endpointFlags(conf.Endpoints)

			for _, ipCfg := range result.IPs {
				ip := ipCfg.Address.IP
				if err := addEndpoint(familyID, ip, flags, ifIndex); err != nil {
					// Treat EEXIST as success for idempotency
					if !os.IsExist(err) {
						return fmt.Errorf("failed to add MPTCP endpoint for %s: %v", ip, err)
					}
				}
			}
		}

		if conf.Limits != nil {
			curSubflows, curAddAddr, err := getLimits(familyID)
			if err != nil {
				return fmt.Errorf("failed to get MPTCP limits: %v", err)
			}

			newSubflows := curSubflows
			if conf.Limits.Subflows != nil {
				newSubflows = *conf.Limits.Subflows
			}
			newAddAddr := curAddAddr
			if conf.Limits.AddAddrAccepted != nil {
				newAddAddr = *conf.Limits.AddAddrAccepted
			}

			if err := setLimits(familyID, newSubflows, newAddAddr); err != nil {
				return fmt.Errorf("failed to set MPTCP limits: %v", err)
			}
		}

		return nil
	})
	if err != nil {
		return fmt.Errorf("cmdAdd failed: %v", err)
	}

	return types.PrintResult(result, conf.CNIVersion)
}

func cmdDel(args *skel.CmdArgs) error {
	conf, result, err := parseConf(args.StdinData)
	if err != nil {
		return err
	}

	if conf.Endpoints == nil {
		return nil
	}

	err = ns.WithNetNSPath(args.Netns, func(_ ns.NetNS) error {
		familyID, err := getMPTCPFamilyID()
		if err != nil {
			// MPTCP not available; nothing to clean up
			return nil
		}

		endpoints, err := listEndpoints(familyID)
		if err != nil {
			// Best effort cleanup
			return nil
		}

		// Build a set of IPs to remove.
		// Prefer IPs from prevResult; fall back to matching by interface index.
		targetIPs := make(map[string]bool)
		if result != nil {
			for _, ipCfg := range result.IPs {
				targetIPs[ipCfg.Address.IP.String()] = true
			}
		}

		for _, ep := range endpoints {
			if ep.Addr == nil {
				continue
			}
			if len(targetIPs) > 0 {
				if !targetIPs[ep.Addr.String()] {
					continue
				}
			} else {
				// No prevResult IPs; try matching by interface
				link, err := netlinksafe.LinkByName(args.IfName)
				if err != nil {
					return nil
				}
				if ep.IfIdx != int32(link.Attrs().Index) {
					continue
				}
			}
			// Ignore errors during cleanup
			_ = delEndpoint(familyID, ep.ID, ep.Addr)
		}

		return nil
	})
	if err != nil {
		_, ok := err.(ns.NSPathNotExistErr)
		if ok {
			return nil
		}
		return err
	}

	return nil
}

func cmdCheck(args *skel.CmdArgs) error {
	conf, result, err := parseConf(args.StdinData)
	if err != nil {
		return err
	}

	if conf.PrevResult == nil {
		return fmt.Errorf("missing prevResult from earlier plugin")
	}

	err = ns.WithNetNSPath(args.Netns, func(_ ns.NetNS) error {
		familyID, err := getMPTCPFamilyID()
		if err != nil {
			return err
		}

		if conf.Endpoints != nil {
			endpoints, err := listEndpoints(familyID)
			if err != nil {
				return fmt.Errorf("failed to list MPTCP endpoints: %v", err)
			}

			expectedFlags := endpointFlags(conf.Endpoints)

			for _, ipCfg := range result.IPs {
				ip := ipCfg.Address.IP
				found := false
				for _, ep := range endpoints {
					if ep.Addr != nil && ep.Addr.Equal(ip) {
						found = true
						if ep.Flags != expectedFlags {
							return fmt.Errorf("MPTCP endpoint %s has flags 0x%x, expected 0x%x", ip, ep.Flags, expectedFlags)
						}
						break
					}
				}
				if !found {
					return fmt.Errorf("MPTCP endpoint for %s not found", ip)
				}
			}
		}

		if conf.Limits != nil {
			curSubflows, curAddAddr, err := getLimits(familyID)
			if err != nil {
				return fmt.Errorf("failed to get MPTCP limits: %v", err)
			}

			if conf.Limits.Subflows != nil && *conf.Limits.Subflows != curSubflows {
				return fmt.Errorf("MPTCP subflows limit is %d, expected %d", curSubflows, *conf.Limits.Subflows)
			}
			if conf.Limits.AddAddrAccepted != nil && *conf.Limits.AddAddrAccepted != curAddAddr {
				return fmt.Errorf("MPTCP add_addr_accepted limit is %d, expected %d", curAddAddr, *conf.Limits.AddAddrAccepted)
			}
		}

		return nil
	})
	if err != nil {
		return err
	}

	return nil
}

func parseConf(data []byte) (*MPTCPNetConf, *current.Result, error) {
	conf := MPTCPNetConf{}
	if err := json.Unmarshal(data, &conf); err != nil {
		return nil, nil, fmt.Errorf("failed to load netconf: %v", err)
	}

	if conf.Endpoints == nil && conf.Limits == nil {
		return nil, nil, fmt.Errorf("at least one of 'endpoints' or 'limits' must be specified")
	}

	if conf.Endpoints != nil {
		if !conf.Endpoints.Signal && !conf.Endpoints.Subflow &&
			!conf.Endpoints.Backup && !conf.Endpoints.Fullmesh {
			return nil, nil, fmt.Errorf("endpoints configured but no flags (signal, subflow, backup, fullmesh) are set")
		}
	}

	if conf.RawPrevResult == nil {
		return &conf, &current.Result{}, nil
	}

	if err := version.ParsePrevResult(&conf.NetConf); err != nil {
		return nil, nil, fmt.Errorf("could not parse prevResult: %v", err)
	}

	result, err := current.NewResultFromResult(conf.PrevResult)
	if err != nil {
		return nil, nil, fmt.Errorf("could not convert result to current version: %v", err)
	}

	return &conf, result, nil
}
