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

	IPMasq            bool   `json:"ipMasq"`
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

func processEndpointArgs(args *skel.CmdArgs, n *NetConf) (*hns.EndpointInfo, error) {
	epInfo := new(hns.EndpointInfo)
	epInfo.NetworkName = n.Name
	epInfo.EndpointName = hns.ConstructEndpointName(args.ContainerID, args.Netns, epInfo.NetworkName)

	if n.IPAM.Type != "" {
		r, err := ipam.ExecAdd(n.IPAM.Type, args.StdinData)
		if err != nil {
			return nil, errors.Annotatef(err, "error while executing IPAM addition")
		}

		// convert whatever the IPAM result was into the current result
		result, err := current.NewResultFromResult(r)
		if err != nil {
			return nil, errors.Annotatef(err, "error while converting the result from IPAM addition")
		}
		if len(result.IPs) == 0 {
			return nil, fmt.Errorf("IPAM plugin return is missing IP config")
		}
		epInfo.IpAddress = result.IPs[0].Address.IP.To4()
		if epInfo.IpAddress == nil {
			return nil, fmt.Errorf("IPAM plugin return is missing valid IP Address")
		}
		epInfo.MacAddress = fmt.Sprintf("%v-%02x-%02x-%02x-%02x", n.EndpointMacPrefix, epInfo.IpAddress[0], epInfo.IpAddress[1], epInfo.IpAddress[2], epInfo.IpAddress[3])

	}
	epInfo.DNS = n.GetDNS()
	if n.LoopbackDSR {
		n.ApplyLoopbackDSRPolicy(&epInfo.IpAddress)
	}
	return epInfo, nil
}

func cmdHcnAdd(args *skel.CmdArgs, n *NetConf) (*current.Result, error) {
	if len(n.EndpointMacPrefix) != 0 {
		if len(n.EndpointMacPrefix) != 5 || n.EndpointMacPrefix[2] != '-' {
			return nil, fmt.Errorf("endpointMacPrefix [%v] is invalid, value must be of the format xx-xx", n.EndpointMacPrefix)
		}
	} else {
		n.EndpointMacPrefix = "0E-2A"
	}

	networkName := n.Name
	hnsNetwork, err := hcsshim.GetHNSNetworkByName(networkName)
	hcnNetwork, err := hcn.GetNetworkByName(networkName)
	if err != nil {
		return nil, errors.Annotatef(err, "error while hcn.GetNetworkByName(%s)", networkName)
	}
	if hcnNetwork == nil {
		return nil, fmt.Errorf("network %v is not found", networkName)
	}
	if hnsNetwork == nil {
		return nil, fmt.Errorf("network %v not found", networkName)
	}

	if !strings.EqualFold(string(hcnNetwork.Type), "Overlay") {
		return nil, fmt.Errorf("network %v is of an unexpected type: %v", networkName, hcnNetwork.Type)
	}

	epName := hns.ConstructEndpointName(args.ContainerID, args.Netns, n.Name)

	hcnEndpoint, err := hns.AddHcnEndpoint(epName, hcnNetwork.Id, args.Netns, func() (*hcn.HostComputeEndpoint, error) {
		epInfo, err := processEndpointArgs(args, n)
		if err != nil {
			return nil, errors.Annotate(err, "error while processing endpoint args")
		}
		epInfo.NetworkId = hcnNetwork.Id
		gatewayAddr := net.ParseIP(hnsNetwork.Subnets[0].GatewayAddress)
		epInfo.Gateway = gatewayAddr.To4()
		n.ApplyDefaultPAPolicy(hnsNetwork.ManagementIP)
		if n.IPMasq {
			n.ApplyOutboundNatPolicy(hnsNetwork.Subnets[0].AddressPrefix)
		}
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
		ipam.ExecDel(n.IPAM.Type, args.StdinData)
		return nil, errors.Annotate(err, "error while constructing HostComputeEndpoint addition result")
	}

	return result, nil
}

func cmdHnsAdd(args *skel.CmdArgs, n *NetConf) (*current.Result, error) {
	success := false

	if len(n.EndpointMacPrefix) != 0 {
		if len(n.EndpointMacPrefix) != 5 || n.EndpointMacPrefix[2] != '-' {
			return nil, fmt.Errorf("endpointMacPrefix [%v] is invalid, value must be of the format xx-xx", n.EndpointMacPrefix)
		}
	} else {
		n.EndpointMacPrefix = "0E-2A"
	}

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

	hnsEndpoint, err := hns.AddHnsEndpoint(epName, hnsNetwork.Id, args.ContainerID, args.Netns, func() (*hcsshim.HNSEndpoint, error) {
		// run the IPAM plugin and get back the config to apply
		r, err := ipam.ExecAdd(n.IPAM.Type, args.StdinData)
		if err != nil {
			return nil, errors.Annotatef(err, "error while ipam.ExecAdd")
		}

		// Convert whatever the IPAM result was into the current Result type
		result, err := current.NewResultFromResult(r)
		if err != nil {
			return nil, errors.Annotatef(err, "error while NewResultFromResult")
		}

		if len(result.IPs) == 0 {
			return nil, fmt.Errorf("IPAM plugin return is missing IP config")
		}

		ipAddr := result.IPs[0].Address.IP.To4()
		if ipAddr == nil {
			return nil, fmt.Errorf("win-overlay doesn't support IPv6 now")
		}

		// conjure a MAC based on the IP for Overlay
		macAddr := fmt.Sprintf("%v-%02x-%02x-%02x-%02x", n.EndpointMacPrefix, ipAddr[0], ipAddr[1], ipAddr[2], ipAddr[3])
		// use the HNS network gateway
		gw := hnsNetwork.Subnets[0].GatewayAddress
		n.ApplyDefaultPAPolicy(hnsNetwork.ManagementIP)
		if n.IPMasq {
			n.ApplyOutboundNatPolicy(hnsNetwork.Subnets[0].AddressPrefix)
		}

		result.DNS = n.GetDNS()
		if n.LoopbackDSR {
			n.ApplyLoopbackDSRPolicy(&ipAddr)
		}
		hnsEndpoint := &hcsshim.HNSEndpoint{
			Name:           epName,
			VirtualNetwork: hnsNetwork.Id,
			DNSServerList:  strings.Join(result.DNS.Nameservers, ","),
			DNSSuffix:      strings.Join(result.DNS.Search, ","),
			GatewayAddress: gw,
			IPAddress:      ipAddr,
			MacAddress:     macAddr,
			Policies:       n.GetHNSEndpointPolicies(),
		}

		return hnsEndpoint, nil
	})
	defer func() {
		if !success {
			ipam.ExecDel(n.IPAM.Type, args.StdinData)
		}
	}()
	if err != nil {
		return nil, errors.Annotatef(err, "error while AddHnsEndpoint(%v,%v,%v)", epName, hnsNetwork.Id, args.ContainerID)
	}

	result, err := hns.ConstructHnsResult(hnsNetwork, hnsEndpoint)
	if err != nil {
		return nil, errors.Annotatef(err, "error while constructResult")
	}

	success = true
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
	}, version.All, bv.BuildString("win-overlay"))
}

func cmdStatus(args *skel.CmdArgs) error {
	conf := NetConf{}
	if err := json.Unmarshal(args.StdinData, &conf); err != nil {
		return fmt.Errorf("failed to load netconf: %w", err)
	}

	if err := ipam.ExecStatus(conf.IPAM.Type, args.StdinData); err != nil {
		return err
	}

	return nil
}
