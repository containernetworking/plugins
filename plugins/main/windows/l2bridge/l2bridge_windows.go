// Copyright 2014 CNI authors
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
	"errors"
	"fmt"
	"log"
	"net"
	"runtime"

	"github.com/Microsoft/hcsshim"
	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/cni/pkg/types/current"
	"github.com/containernetworking/cni/pkg/version"
	"github.com/containernetworking/plugins/pkg/hns"
	"github.com/containernetworking/plugins/pkg/ipam"
	"strings"
)

type NetConf struct {
	hns.NetConf

	ipmasq               bool      `json:"ipmasq,omitempty"`
	clusterNetworkPrefix net.IPNet `json:"clusterprefix,omitempty"`
}
type K8sCniEnvArgs struct {
	types.CommonArgs
	K8S_POD_NAMESPACE          types.UnmarshallableString `json:"K8S_POD_NAMESPACE,omitempty"`
	K8S_POD_NAME               types.UnmarshallableString `json:"K8S_POD_NAME,omitempty"`
	K8S_POD_INFRA_CONTAINER_ID types.UnmarshallableString `json:"K8S_POD_INFRA_CONTAINER_ID,omitempty"`
}

func init() {
	// this ensures that main runs only on main thread (thread group leader).
	// since namespace ops (unshare, setns) are done for a single thread, we
	// must ensure that the goroutine does not jump from OS thread to thread
	runtime.LockOSThread()
}

func parseCniArgs(args string) (*K8sCniEnvArgs, error) {
	podConfig := K8sCniEnvArgs{}
	err := types.LoadArgs(args, &podConfig)
	if err != nil {
		return nil, err
	}
	return &podConfig, nil
}

func loadNetConf(bytes []byte) (*NetConf, string, error) {
	n := &NetConf{}
	if err := json.Unmarshal(bytes, n); err != nil {
		return nil, "", fmt.Errorf("failed to load netconf: %v", err)
	}
	log.Printf("Loaded NetConf %v", n)
	return n, n.CNIVersion, nil
}

func cmdAdd(args *skel.CmdArgs) error {
	log.Printf("[cni-net] Processing ADD command with args {ContainerID:%v Netns:%v IfName:%v Args:%v Path:%v}.",
		args.ContainerID, args.Netns, args.IfName, args.Args, args.Path)
	n, cniVersion, err := loadNetConf(args.StdinData)
	if err != nil {
		return err
	}
	cniargs, err := parseCniArgs(args.Args)
	k8sNamespace := "default"
	if err == nil {
		k8sNamespace = string(cniargs.K8S_POD_NAMESPACE)
	}
	networkName := n.Name
	hnsNetwork, err := hcsshim.GetHNSNetworkByName(networkName)
	if err != nil {
		return err
	}

	if hnsNetwork == nil {
		return fmt.Errorf("network %v not found", networkName)
	}

	if !strings.EqualFold(hnsNetwork.Type, "L2Bridge") {
		return fmt.Errorf("network %v is of an unexpected type: %v", networkName, hnsNetwork.Type)
	}

	epName := hns.ConstructEndpointName(args.ContainerID, args.Netns, n.Name)

	hnsEndpoint, err := hns.ProvisionEndpoint(epName, hnsNetwork.Id, args.ContainerID, func() (*hcsshim.HNSEndpoint, error) {
		// run the IPAM plugin and get back the config to apply
		r, err := ipam.ExecAdd(n.IPAM.Type, args.StdinData)
		if err != nil {
			return nil, err
		}

		// Convert whatever the IPAM result was into the current Result type
		result, err := current.NewResultFromResult(r)
		if err != nil {
			return nil, err
		}

		if len(result.IPs) == 0 {
			return nil, errors.New("IPAM plugin return is missing IP config")
		}

		// Calculate gateway for bridge network (needs to be x.2)
		gw := result.IPs[0].Address.IP.Mask(result.IPs[0].Address.Mask)
		gw[len(gw)-1] += 2

		// NAT based on the the configured cluster network
		if n.ipmasq {
			n.ApplyOutboundNatPolicy(n.clusterNetworkPrefix.String())
		}

		nameservers := strings.Join(n.DNS.Nameservers, ",")
		if result.DNS.Nameservers != nil {
			nameservers = strings.Join(result.DNS.Nameservers, ",")
		}

		dnsSuffix := ""
		if len(n.DNS.Search) > 0 {
			dnsSuffix = k8sNamespace + "." + n.DNS.Search[0]
		}

		hnsEndpoint := &hcsshim.HNSEndpoint{
			Name:           epName,
			VirtualNetwork: hnsNetwork.Id,
			DNSServerList:  nameservers,
			DNSSuffix:      dnsSuffix,
			GatewayAddress: gw.String(),
			IPAddress:      result.IPs[0].Address.IP,
			Policies:       n.MarshalPolicies(),
		}

		log.Printf("Adding Hns Endpoint %v", hnsEndpoint)
		return hnsEndpoint, nil
	})

	if err != nil {
		return err
	}

	result, err := hns.ConstructResult(hnsNetwork, hnsEndpoint)
	if err != nil {
		return err
	}

	return types.PrintResult(result, cniVersion)
}

func cmdDel(args *skel.CmdArgs) error {
	log.Printf("[cni-net] Processing DEL command with args {ContainerID:%v Netns:%v IfName:%v Args:%v Path:%v}.",
		args.ContainerID, args.Netns, args.IfName, args.Args, args.Path)
	n, _, err := loadNetConf(args.StdinData)
	if err != nil {
		return err
	}

	if err := ipam.ExecDel(n.IPAM.Type, args.StdinData); err != nil {
		return err
	}

	if args.Netns == "" {
		return nil
	}

	epName := hns.ConstructEndpointName(args.ContainerID, args.Netns, n.Name)

	return hns.DeprovisionEndpoint(epName, args.Netns, args.ContainerID)
}

func main() {
	skel.PluginMain(cmdAdd, cmdDel, version.All)
}
