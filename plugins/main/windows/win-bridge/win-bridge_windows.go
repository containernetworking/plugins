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

package main

import (
	"encoding/json"
	"fmt"
	"runtime"
	"strings"

	"github.com/Microsoft/hcsshim"
	"github.com/Microsoft/hcsshim/hcn"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	current "github.com/containernetworking/cni/pkg/types/100"
	"github.com/containernetworking/cni/pkg/version"

	"github.com/containernetworking/plugins/pkg/errors"
	"github.com/containernetworking/plugins/pkg/hns"
	"github.com/containernetworking/plugins/pkg/ipam"
	bv "github.com/containernetworking/plugins/pkg/utils/buildversion"
)

type NetConf struct {
	hns.NetConf

	IPMasqNetwork string `json:"ipMasqNetwork,omitempty"`
}

func init() {
	// this ensures that main runs only on main thread (thread group leader).
	// since namespace ops (unshare, setns) are done for a single thread, we
	// must ensure that the goroutine does not jump from OS thread to thread
	runtime.LockOSThread()
}

func loadNetConf(bytes []byte) (*NetConf, string, error) {
	n := &NetConf{}
	if err := json.Unmarshal(bytes, n); err != nil {
		return nil, "", fmt.Errorf("failed to load netconf: %v", err)
	}
	return n, n.CNIVersion, nil
}

func processEndpointArgs(args *skel.CmdArgs, n *NetConf) (*hns.EndpointInfo, error) {
	epInfo := new(hns.EndpointInfo)
	epInfo.NetworkName = n.Name
	epInfo.EndpointName = hns.ConstructEndpointName(args.ContainerID, args.Netns, epInfo.NetworkName)

	// it's not necessary to have have an IPAM in windows as HNS can provide IP/GW
	if n.IPAM.Type != "" {
		r, err := ipam.ExecAdd(n.IPAM.Type, args.StdinData)
		if err != nil {
			return nil, errors.Annotatef(err, "error while executing IPAM addition")
		}

		// convert whatever the IPAM result was into the current result
		result, err := current.NewResultFromResult(r)
		if err != nil {
			return nil, errors.Annotatef(err, "error while converting the result from IPAM addition")
		} else {
			if len(result.IPs) == 0 {
				return nil, fmt.Errorf("IPAM plugin return is missing IP config")
			}
			epInfo.IpAddress = result.IPs[0].Address.IP
			epInfo.Gateway = result.IPs[0].Address.IP.Mask(result.IPs[0].Address.Mask)

			// Calculate gateway for bridge network (needs to be x.2)
			epInfo.Gateway[len(epInfo.Gateway)-1] += 2
		}
	}

	// configure sNAT exception
	n.ApplyOutboundNatPolicy(n.IPMasqNetwork)

	// add port mapping if any present
	n.ApplyPortMappingPolicy(n.RuntimeConfig.PortMaps)

	epInfo.DNS = n.GetDNS()

	return epInfo, nil
}

func cmdHnsAdd(args *skel.CmdArgs, n *NetConf) (*current.Result, error) {
	networkName := n.Name
	hnsNetwork, err := hcsshim.GetHNSNetworkByName(networkName)
	if err != nil {
		return nil, errors.Annotatef(err, "error while getting network %v", networkName)
	}
	if hnsNetwork == nil {
		return nil, fmt.Errorf("network %v is not found", networkName)
	}
	if !strings.EqualFold(hnsNetwork.Type, "L2Bridge") && !strings.EqualFold(hnsNetwork.Type, "L2Tunnel") {
		return nil, fmt.Errorf("network %v is of unexpected type: %v", networkName, hnsNetwork.Type)
	}

	epName := hns.ConstructEndpointName(args.ContainerID, args.Netns, n.Name)
	hnsEndpoint, err := hns.AddHnsEndpoint(epName, hnsNetwork.Id, args.ContainerID, args.Netns, func() (*hcsshim.HNSEndpoint, error) {
		epInfo, err := processEndpointArgs(args, n)
		if err != nil {
			return nil, errors.Annotate(err, "error while processing endpoint args")
		}
		epInfo.NetworkId = hnsNetwork.Id

		hnsEndpoint, err := hns.GenerateHnsEndpoint(epInfo, &n.NetConf)
		if err != nil {
			return nil, errors.Annotate(err, "error while generating HNSEndpoint")
		}
		return hnsEndpoint, nil
	})
	if err != nil {
		return nil, errors.Annotate(err, "error while adding HNSEndpoint")
	}

	result, err := hns.ConstructHnsResult(hnsNetwork, hnsEndpoint)
	if err != nil {
		return nil, errors.Annotate(err, "error while constructing HNSEndpoint addition result")
	}
	return result, nil
}

func cmdHcnAdd(args *skel.CmdArgs, n *NetConf) (*current.Result, error) {
	networkName := n.Name
	hcnNetwork, err := hcn.GetNetworkByName(networkName)
	if err != nil {
		return nil, errors.Annotatef(err, "error while getting network %v", networkName)
	}
	if hcnNetwork == nil {
		return nil, fmt.Errorf("network %v is not found", networkName)
	}
	if hcnNetwork.Type != hcn.L2Bridge && hcnNetwork.Type != hcn.L2Tunnel {
		return nil, fmt.Errorf("network %v is of unexpected type: %v", networkName, hcnNetwork.Type)
	}

	epName := hns.ConstructEndpointName(args.ContainerID, args.Netns, n.Name)
	hcnEndpoint, err := hns.AddHcnEndpoint(epName, hcnNetwork.Id, args.Netns, func() (*hcn.HostComputeEndpoint, error) {
		epInfo, err := processEndpointArgs(args, n)
		if err != nil {
			return nil, errors.Annotate(err, "error while processing endpoint args")
		}
		epInfo.NetworkId = hcnNetwork.Id

		hcnEndpoint, err := hns.GenerateHcnEndpoint(epInfo, &n.NetConf)
		if err != nil {
			return nil, errors.Annotate(err, "error while generating HostComputeEndpoint")
		}
		return hcnEndpoint, nil
	})
	if err != nil {
		return nil, errors.Annotate(err, "error while adding HostComputeEndpoint")
	}

	result, err := hns.ConstructHcnResult(hcnNetwork, hcnEndpoint)
	if err != nil {
		return nil, errors.Annotate(err, "error while constructing HostComputeEndpoint addition result")
	}
	return result, nil
}

func cmdAdd(args *skel.CmdArgs) error {
	n, cniVersion, err := loadNetConf(args.StdinData)
	if err != nil {
		return err
	}

	var result *current.Result
	if n.ApiVersion == 2 {
		result, err = cmdHcnAdd(args, n)
	} else {
		result, err = cmdHnsAdd(args, n)
	}
	if err != nil {
		ipam.ExecDel(n.IPAM.Type, args.StdinData)
		return err
	}

	return types.PrintResult(result, cniVersion)
}

func cmdDel(args *skel.CmdArgs) error {
	n, _, err := loadNetConf(args.StdinData)
	if err != nil {
		return err
	}

	if n.IPAM.Type != "" {
		if err := ipam.ExecDel(n.IPAM.Type, args.StdinData); err != nil {
			return err
		}
	}
	epName := hns.ConstructEndpointName(args.ContainerID, args.Netns, n.Name)

	if n.ApiVersion == 2 {
		return hns.RemoveHcnEndpoint(epName)
	}
	return hns.RemoveHnsEndpoint(epName, args.Netns, args.ContainerID)
}

func cmdCheck(_ *skel.CmdArgs) error {
	// TODO: implement
	return nil
}

func main() {
	skel.PluginMainFuncs(skel.CNIFuncs{
		Add:    cmdAdd,
		Check:  cmdCheck,
		Del:    cmdDel,
		Status: cmdStatus,
		/* FIXME GC */
	}, version.All, bv.BuildString("win-bridge"))
}

func cmdStatus(args *skel.CmdArgs) error {
	conf := NetConf{}
	if err := json.Unmarshal(args.StdinData, &conf); err != nil {
		return fmt.Errorf("failed to load netconf: %w", err)
	}

	if conf.IPAM.Type != "" {
		if err := ipam.ExecStatus(conf.IPAM.Type, args.StdinData); err != nil {
			return err
		}
	}

	return nil
}
