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
	"net"
	"os"
	"runtime"
	"strings"

	"github.com/Microsoft/hcsshim"
	"github.com/Microsoft/hcsshim/hcn"
	"github.com/juju/errors"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/cni/pkg/types/current"
	"github.com/containernetworking/cni/pkg/version"

	"github.com/containernetworking/plugins/pkg/hns"
	"github.com/containernetworking/plugins/pkg/ipam"
	bv "github.com/containernetworking/plugins/pkg/utils/buildversion"
)

type NetConf struct {
	hns.NetConf

	IPMasq            bool   `json:"ipMasq"`
	ApiVersion        int    `json:"ApiVersion"`
	EndpointMacPrefix string `json:"endpointMacPrefix,omitempty"`
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

func ProcessEndpointArgs(args *skel.CmdArgs, n *NetConf) (*hns.EndpointInfo, error) {
	if len(n.EndpointMacPrefix) != 0 {
		if len(n.EndpointMacPrefix) != 5 || n.EndpointMacPrefix[2] != '-' {
			return nil, fmt.Errorf("endpointMacPrefix [%v] is invalid, value must be of the format xx-xx", n.EndpointMacPrefix)
		}
	} else {
		n.EndpointMacPrefix = "0E-2A"
	}

	epInfo := new(hns.EndpointInfo)
	epInfo.NetworkName = n.Name
	epInfo.EndpointName = hns.ConstructEndpointName(args.ContainerID, args.Netns, epInfo.NetworkName)

	// run the IPAM plugin and get back the config to apply
	r, err := ipam.ExecAdd(n.IPAM.Type, args.StdinData)
	if err != nil {
		return nil, errors.Annotatef(err, "error while ipam.ExecAdd")
	}

	result, err := current.NewResultFromResult(r)
	if err != nil {
		return nil, errors.Annotatef(err, "error while NewResultFromResult")
	}

	if len(result.IPs) == 0 {
		return nil, errors.New("IPAM plugin return is missing IP config")
	}

	ipAddr := result.IPs[0].Address.IP.To4()
	if ipAddr == nil {
		return nil, errors.New("win-overlay doesn't support IPv6 now")
	}
	epInfo.IpAddress = ipAddr
	// conjure a MAC based on the IP for Overlay
	macAddr := fmt.Sprintf("%v-%02x-%02x-%02x-%02x", n.EndpointMacPrefix, ipAddr[0], ipAddr[1], ipAddr[2], ipAddr[3])
	epInfo.MacAddress = macAddr
	epInfo.DNS = n.GetDNS()
	return epInfo, nil
}

func cmdHnsAdd(args *skel.CmdArgs, n *NetConf) (*current.Result, error) {
	networkName := n.Name
	hnsNetwork, err := hcsshim.GetHNSNetworkByName(networkName)
	if err != nil {
		return nil, errors.Annotatef(err, "error while GETHNSNewtorkByName(%s)", networkName)
	}

	if hnsNetwork == nil {
		return nil, fmt.Errorf("network %v not found", networkName)
	}

	if !strings.EqualFold(hnsNetwork.Type, "Overlay") {
		return nil, fmt.Errorf("network %v is of an unexpected type: %v", networkName, hnsNetwork.Type)
	}

	epName := hns.ConstructEndpointName(args.ContainerID, args.Netns, n.Name)

	hnsEndpoint, err := hns.ProvisionEndpoint(epName, hnsNetwork.Id, args.ContainerID, args.Netns, func() (*hcsshim.HNSEndpoint, error) {
		epInfo, err := ProcessEndpointArgs(args, n)
		epInfo.NetworkId = hnsNetwork.Id
		if err != nil {
			return nil, errors.Annotatef(err, "error while ProcessEndpointArgs")
		}
		// use the HNS network gateway
		epInfo.Gateway = net.ParseIP(hnsNetwork.Subnets[0].GatewayAddress)
		n.ApplyDefaultPAPolicy(hnsNetwork.ManagementIP)
		if n.IPMasq {
			n.ApplyOutboundNatPolicy(hnsNetwork.Subnets[0].AddressPrefix)
		}
		hnsEndpoint, err := hns.GenerateHnsEndpoint(epInfo, &n.NetConf)
		if err != nil {
			return nil, errors.Annotatef(err, "error while GenerateHnsEndpoint")
		}
		return hnsEndpoint, nil
	})
	if err != nil {
		return nil, errors.Annotatef(err, "error while ProvisionEndpoint(%v,%v,%v)", epName, hnsNetwork.Id, args.ContainerID)
	}

	result, err := hns.ConstructResult(hnsNetwork, hnsEndpoint)
	if err != nil {
		return nil, errors.Annotatef(err, "error while constructResult")
	}

	return result, nil
}

func cmdHcnAdd(args *skel.CmdArgs, n *NetConf) (*current.Result, error) {
	networkName := n.Name
	hcnNetwork, err := hcn.GetNetworkByName(networkName)
	if err != nil {
		return nil, errors.Annotatef(err, "error while GetNetworkByName(%s)", networkName)
	}

	if hcnNetwork == nil {
		return nil, fmt.Errorf("network %v not found", networkName)
	}

	if hcnNetwork.Type != hcn.Overlay {
		return nil, fmt.Errorf("network %v is of unexpected type: %v", networkName, hcnNetwork.Type)
	}

	epName := hns.ConstructEndpointName(args.ContainerID, args.Netns, n.Name)

	hcnEndpoint, err := hns.AddHcnEndpoint(epName, hcnNetwork.Id, args.Netns, func() (*hcn.HostComputeEndpoint, error) {
		epInfo, err := ProcessEndpointArgs(args, n)
		if err != nil {
			return nil, errors.Annotatef(err, "error while ProcessEndpointArgs")
		}
		epInfo.NetworkId = hcnNetwork.Id
		epInfo.Gateway = net.ParseIP(hcnNetwork.Ipams[0].Subnets[0].Routes[0].NextHop)
		var providerAddressPolicySetting hcn.ProviderAddressEndpointPolicySetting
		for _, po := range hcnNetwork.Policies {
			if po.Type == hcn.ProviderAddress {

				if err := json.Unmarshal([]byte(po.Settings), &providerAddressPolicySetting); err != nil {
					fmt.Errorf("Error Unmarshaling Network Policy err: %v settings: %v", err, po.Settings)
					continue
				}
			}
		}
		n.ApplyDefaultPAPolicy(providerAddressPolicySetting.ProviderAddress)

		if n.IPMasq {
			n.ApplyOutboundNatPolicy(hcnNetwork.Ipams[0].Subnets[0].IpAddressPrefix)
		}

		hcnEndpoint, err := hns.GenerateHcnEndpoint(epInfo, &n.NetConf)
		if err != nil {
			return nil, errors.Annotatef(err, "error while GenerateHcnEndpoint")
		}
		return hcnEndpoint, nil
	})
	if err != nil {
		return nil, errors.Annotatef(err, "error while AddHcnEndpoint(%v,%v,%v)", epName, hcnNetwork.Id, args.Netns)
	}

	result, err := hns.ConstructHcnResult(hcnNetwork, hcnEndpoint)
	if err != nil {
		return nil, errors.Annotatef(err, "error while ConstructHcnResult")
	}

	return result, nil
}

func cmdAdd(args *skel.CmdArgs) error {
	n, cniVersion, err := loadNetConf(args.StdinData)
	if err != nil {
		return errors.Annotate(err, "error while loadNetConf")
	}

	var result *current.Result
	if n.ApiVersion == 2 {
		result, err = cmdHcnAdd(args, n)
	} else {
		result, err = cmdHnsAdd(args, n)
	}

	if err != nil {
		os.Setenv("CNI_COMMAND", "DEL")
		ipam.ExecDel(n.IPAM.Type, args.StdinData)
		os.Setenv("CNI_COMMAND", "ADD")
		return errors.Annotate(err, "error while executing ADD command")
	}

	if result == nil {
		return errors.New("result for ADD not populated correctly")
	}
	return types.PrintResult(result, cniVersion)
}

func cmdDel(args *skel.CmdArgs) error {
	n, _, err := loadNetConf(args.StdinData)
	if err != nil {
		return err
	}

	if err := ipam.ExecDel(n.IPAM.Type, args.StdinData); err != nil {
		return err
	}

	epName := hns.ConstructEndpointName(args.ContainerID, args.Netns, n.Name)

	if n.ApiVersion == 2 {
		return hns.RemoveHcnEndpoint(epName)
	} else {
		return hns.DeprovisionEndpoint(epName, args.Netns, args.ContainerID)
	}

}

func cmdCheck(_ *skel.CmdArgs) error {
	// TODO: implement
	return nil
}

func main() {
	skel.PluginMain(cmdAdd, cmdCheck, cmdDel, version.PluginSupports("0.1.0", "0.2.0", "0.3.0"), bv.BuildString("win-overlay"))
}
