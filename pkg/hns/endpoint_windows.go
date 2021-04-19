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
	"fmt"
	"net"
	"strings"

	"github.com/Microsoft/hcsshim"
	"github.com/Microsoft/hcsshim/hcn"

	"github.com/containernetworking/cni/pkg/types"
	current "github.com/containernetworking/cni/pkg/types/100"

	"github.com/containernetworking/plugins/pkg/errors"
)

const (
	pauseContainerNetNS = "none"
)

type EndpointInfo struct {
	EndpointName string
	DNS          types.DNS
	NetworkName  string
	NetworkId    string
	Gateway      net.IP
	IpAddress    net.IP
}

// GetSandboxContainerID returns the sandbox ID of this pod.
func GetSandboxContainerID(containerID string, netNs string) string {
	if len(netNs) != 0 && netNs != pauseContainerNetNS {
		splits := strings.SplitN(netNs, ":", 2)
		if len(splits) == 2 {
			containerID = splits[1]
		}
	}

	return containerID
}

// GetIpString returns the given IP in string.
func GetIpString(ip *net.IP) string {
	if len(*ip) == 0 {
		return ""
	} else {
		return ip.String()
	}
}

// GetDefaultDestinationPrefix returns the default destination prefix according to the given IP type.
func GetDefaultDestinationPrefix(ip *net.IP) string {
	destinationPrefix := "0.0.0.0/0"
	if ipv6 := ip.To4(); ipv6 == nil {
		destinationPrefix = "::/0"
	}
	return destinationPrefix
}

// ConstructEndpointName constructs endpoint id which is used to identify an endpoint from HNS/HCN.
func ConstructEndpointName(containerID string, netNs string, networkName string) string {
	return GetSandboxContainerID(containerID, netNs) + "_" + networkName
}

// GenerateHnsEndpoint generates an HNSEndpoint with given info and config.
func GenerateHnsEndpoint(epInfo *EndpointInfo, n *NetConf) (*hcsshim.HNSEndpoint, error) {
	// run the IPAM plugin and get back the config to apply
	hnsEndpoint, err := hcsshim.GetHNSEndpointByName(epInfo.EndpointName)
	if err != nil && !hcsshim.IsNotExist(err) {
		return nil, errors.Annotatef(err, "failed to get HNSEndpoint %s", epInfo.EndpointName)
	}

	if hnsEndpoint != nil {
		if strings.EqualFold(hnsEndpoint.VirtualNetwork, epInfo.NetworkId) {
			return nil, fmt.Errorf("HNSEndpoint %s is already existed", epInfo.EndpointName)
		}
		// remove endpoint if corrupted
		if _, err = hnsEndpoint.Delete(); err != nil {
			return nil, errors.Annotatef(err, "failed to delete corrupted HNSEndpoint %s", epInfo.EndpointName)
		}
	}

	if n.LoopbackDSR {
		n.ApplyLoopbackDSR(&epInfo.IpAddress)
	}
	hnsEndpoint = &hcsshim.HNSEndpoint{
		Name:           epInfo.EndpointName,
		VirtualNetwork: epInfo.NetworkId,
		DNSServerList:  strings.Join(epInfo.DNS.Nameservers, ","),
		DNSSuffix:      strings.Join(epInfo.DNS.Search, ","),
		GatewayAddress: GetIpString(&epInfo.Gateway),
		IPAddress:      epInfo.IpAddress,
		Policies:       n.MarshalPolicies(),
	}
	return hnsEndpoint, nil
}

// RemoveHnsEndpoint detaches the given name endpoint from container specified by containerID,
// or removes the given name endpoint completely.
func RemoveHnsEndpoint(epName string, netns string, containerID string) error {
	if len(netns) == 0 {
		return nil
	}

	hnsEndpoint, err := hcsshim.GetHNSEndpointByName(epName)
	if err != nil {
		if hcsshim.IsNotExist(err) {
			return nil
		}
		return errors.Annotatef(err, "failed to find HNSEndpoint %s", epName)
	}

	// for shared endpoint, detach it from the container
	if netns != pauseContainerNetNS {
		_ = hnsEndpoint.ContainerDetach(containerID)
		return nil
	}

	// for removing the endpoint completely, hot detach is used at first
	_ = hcsshim.HotDetachEndpoint(containerID, hnsEndpoint.Id)
	_, _ = hnsEndpoint.Delete()
	return nil
}

type HnsEndpointMakerFunc func() (*hcsshim.HNSEndpoint, error)

// AddHnsEndpoint attaches an HNSEndpoint to a container specified by containerID.
func AddHnsEndpoint(epName string, expectedNetworkId string, containerID string, netns string, makeEndpoint HnsEndpointMakerFunc) (*hcsshim.HNSEndpoint, error) {
	hnsEndpoint, err := hcsshim.GetHNSEndpointByName(epName)
	if err != nil {
		if !hcsshim.IsNotExist(err) {
			return nil, errors.Annotatef(err, "failed to find HNSEndpoint %s", epName)
		}
	}

	// for shared endpoint, we expect that the endpoint already exists
	if netns != pauseContainerNetNS {
		if hnsEndpoint == nil {
			return nil, errors.Annotatef(err, "failed to find HNSEndpoint %s", epName)
		}
	}

	// verify the existing endpoint is corrupted or not
	if hnsEndpoint != nil {
		if !strings.EqualFold(hnsEndpoint.VirtualNetwork, expectedNetworkId) {
			if _, err := hnsEndpoint.Delete(); err != nil {
				return nil, errors.Annotatef(err, "failed to delete corrupted HNSEndpoint %s", epName)
			}
			hnsEndpoint = nil
		}
	}

	// create endpoint if not found
	var isNewEndpoint bool
	if hnsEndpoint == nil {
		if hnsEndpoint, err = makeEndpoint(); err != nil {
			return nil, errors.Annotate(err, "failed to make a new HNSEndpoint")
		}
		if hnsEndpoint, err = hnsEndpoint.Create(); err != nil {
			return nil, errors.Annotate(err, "failed to create the new HNSEndpoint")
		}
		isNewEndpoint = true
	}

	// attach to container
	if err := hcsshim.HotAttachEndpoint(containerID, hnsEndpoint.Id); err != nil {
		if isNewEndpoint {
			if err := RemoveHnsEndpoint(epName, netns, containerID); err != nil {
				return nil, errors.Annotatef(err, "failed to remove the new HNSEndpoint %s after attaching container %s failure", hnsEndpoint.Id, containerID)
			}
		} else if hcsshim.ErrComputeSystemDoesNotExist == err {
			return hnsEndpoint, nil
		}
		return nil, errors.Annotatef(err, "failed to attach container %s to HNSEndpoint %s", containerID, hnsEndpoint.Id)
	}
	return hnsEndpoint, nil
}

// ConstructHnsResult constructs the CNI result for the HNSEndpoint.
func ConstructHnsResult(hnsNetwork *hcsshim.HNSNetwork, hnsEndpoint *hcsshim.HNSEndpoint) (*current.Result, error) {
	resultInterface := &current.Interface{
		Name: hnsEndpoint.Name,
		Mac:  hnsEndpoint.MacAddress,
	}
	_, ipSubnet, err := net.ParseCIDR(hnsNetwork.Subnets[0].AddressPrefix)
	if err != nil {
		return nil, errors.Annotatef(err, "failed to parse CIDR from %s", hnsNetwork.Subnets[0].AddressPrefix)
	}

	resultIPConfig := &current.IPConfig{
		Address: net.IPNet{
			IP:   hnsEndpoint.IPAddress,
			Mask: ipSubnet.Mask},
		Gateway: net.ParseIP(hnsEndpoint.GatewayAddress),
	}
	result := &current.Result{
		CNIVersion: current.ImplementedSpecVersion,
		Interfaces: []*current.Interface{resultInterface},
		IPs:        []*current.IPConfig{resultIPConfig},
		DNS: types.DNS{
			Search:      strings.Split(hnsEndpoint.DNSSuffix, ","),
			Nameservers: strings.Split(hnsEndpoint.DNSServerList, ","),
		},
	}

	return result, nil
}

// GenerateHcnEndpoint generates a HostComputeEndpoint with given info and config.
func GenerateHcnEndpoint(epInfo *EndpointInfo, n *NetConf) (*hcn.HostComputeEndpoint, error) {
	// run the IPAM plugin and get back the config to apply
	hcnEndpoint, err := hcn.GetEndpointByName(epInfo.EndpointName)
	if err != nil && !hcn.IsNotFoundError(err) {
		return nil, errors.Annotatef(err, "failed to get endpoint %q", epInfo.EndpointName)
	}

	if hcnEndpoint != nil {
		// If the endpont already exists, then we should return error unless
		// the endpoint is based on a different network then delete
		// should that fail return error
		if !strings.EqualFold(hcnEndpoint.HostComputeNetwork, epInfo.NetworkId) {
			err = hcnEndpoint.Delete()
			if err != nil {
				return nil, errors.Annotatef(err, "failed to delete endpoint %s", epInfo.EndpointName)
			}
		} else {
			return nil, fmt.Errorf("endpoint %q already exits", epInfo.EndpointName)
		}
	}

	if hcnEndpoint == nil {
		routes := []hcn.Route{
			{
				NextHop:           GetIpString(&epInfo.Gateway),
				DestinationPrefix: GetDefaultDestinationPrefix(&epInfo.Gateway),
			},
		}

		hcnDns := hcn.Dns{
			Search:     epInfo.DNS.Search,
			ServerList: epInfo.DNS.Nameservers,
		}

		hcnIpConfig := hcn.IpConfig{
			IpAddress: GetIpString(&epInfo.IpAddress),
		}
		ipConfigs := []hcn.IpConfig{hcnIpConfig}

		if n.LoopbackDSR {
			n.ApplyLoopbackDSR(&epInfo.IpAddress)
		}
		hcnEndpoint = &hcn.HostComputeEndpoint{
			SchemaVersion:      hcn.Version{Major: 2},
			Name:               epInfo.EndpointName,
			HostComputeNetwork: epInfo.NetworkId,
			Dns:                hcnDns,
			Routes:             routes,
			IpConfigurations:   ipConfigs,
			Policies: func() []hcn.EndpointPolicy {
				if n.HcnPolicyArgs == nil {
					n.HcnPolicyArgs = []hcn.EndpointPolicy{}
				}
				return n.HcnPolicyArgs
			}(),
		}
	}
	return hcnEndpoint, nil
}

// RemoveHcnEndpoint removes the given name endpoint from namespace.
func RemoveHcnEndpoint(epName string) error {
	hcnEndpoint, err := hcn.GetEndpointByName(epName)
	if hcn.IsNotFoundError(err) {
		return nil
	} else if err != nil {
		_ = fmt.Errorf("[win-cni] Failed to find endpoint %v, err:%v", epName, err)
		return err
	}
	if hcnEndpoint != nil {
		err = hcnEndpoint.Delete()
		if err != nil {
			return fmt.Errorf("[win-cni] Failed to delete endpoint %v, err:%v", epName, err)
		}
	}
	return nil
}

type HcnEndpointMakerFunc func() (*hcn.HostComputeEndpoint, error)

// AddHcnEndpoint attaches a HostComputeEndpoint to the given namespace.
func AddHcnEndpoint(epName string, expectedNetworkId string, namespace string, makeEndpoint HcnEndpointMakerFunc) (*hcn.HostComputeEndpoint, error) {
	hcnEndpoint, err := makeEndpoint()
	if err != nil {
		return nil, errors.Annotate(err, "failed to make a new HostComputeEndpoint")
	}

	if hcnEndpoint, err = hcnEndpoint.Create(); err != nil {
		return nil, errors.Annotate(err, "failed to create the new HostComputeEndpoint")
	}

	err = hcn.AddNamespaceEndpoint(namespace, hcnEndpoint.Id)
	if err != nil {
		err := RemoveHcnEndpoint(epName)
		if err != nil {
			return nil, errors.Annotatef(err, "failed to remote the new HostComputeEndpoint %s after adding HostComputeNamespace %s failure", epName, namespace)
		}
		return nil, errors.Annotatef(err, "failed to add HostComputeEndpoint %s to HostComputeNamespace %s", epName, namespace)
	}
	return hcnEndpoint, nil
}

// ConstructHcnResult constructs the CNI result for the HostComputeEndpoint.
func ConstructHcnResult(hcnNetwork *hcn.HostComputeNetwork, hcnEndpoint *hcn.HostComputeEndpoint) (*current.Result, error) {
	resultInterface := &current.Interface{
		Name: hcnEndpoint.Name,
		Mac:  hcnEndpoint.MacAddress,
	}
	_, ipSubnet, err := net.ParseCIDR(hcnNetwork.Ipams[0].Subnets[0].IpAddressPrefix)
	if err != nil {
		return nil, err
	}

	ipAddress := net.ParseIP(hcnEndpoint.IpConfigurations[0].IpAddress)
	resultIPConfig := &current.IPConfig{
		Address: net.IPNet{
			IP:   ipAddress,
			Mask: ipSubnet.Mask},
		Gateway: net.ParseIP(hcnEndpoint.Routes[0].NextHop),
	}
	result := &current.Result{
		CNIVersion: current.ImplementedSpecVersion,
		Interfaces: []*current.Interface{resultInterface},
		IPs:        []*current.IPConfig{resultIPConfig},
		DNS: types.DNS{
			Search:      hcnEndpoint.Dns.Search,
			Nameservers: hcnEndpoint.Dns.ServerList,
		},
	}

	return result, nil
}
