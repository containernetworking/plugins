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
	"github.com/containernetworking/cni/pkg/types/current"
	"github.com/juju/errors"
)

const (
	pauseContainerNetNS = "none"
)

// GetSandboxContainerID returns the sandbox ID of this pod
func GetSandboxContainerID(containerID string, netNs string) string {
	if len(netNs) != 0 && netNs != pauseContainerNetNS {
		splits := strings.SplitN(netNs, ":", 2)
		if len(splits) == 2 {
			containerID = splits[1]
		}
	}

	return containerID
}

// ConstructEndpointName constructs enpointId which is used to identify an endpoint from HNS
// There is a special consideration for netNs name here, which is required for Windows Server 1709
// containerID is the Id of the container on which the endpoint is worked on
func ConstructEndpointName(containerID string, netNs string, networkName string) string {
	return GetSandboxContainerID(containerID, netNs) + "_" + networkName
}

// DeprovisionEndpoint removes an endpoint from the container by sending a Detach request to HNS
// For shared endpoint, ContainerDetach is used
// for removing the endpoint completely, HotDetachEndpoint is used
func DeprovisionEndpoint(epName string, netns string, containerID string) error {
	if len(netns) == 0 {
		return nil
	}

	hnsEndpoint, err := hcsshim.GetHNSEndpointByName(epName)
	if err != nil {
		return errors.Annotatef(err, "failed to find HNSEndpoint %s", epName)
	}

	if netns != pauseContainerNetNS {
		// Shared endpoint removal. Do not remove the endpoint.
		hnsEndpoint.ContainerDetach(containerID)
		return nil
	}

	// Do not consider this as failure, else this would leak endpoints
	hcsshim.HotDetachEndpoint(containerID, hnsEndpoint.Id)

	// Do not return error
	hnsEndpoint.Delete()

	return nil
}

type EndpointMakerFunc func() (*hcsshim.HNSEndpoint, error)

// ProvisionEndpoint provisions an endpoint to a container specified by containerID.
// If an endpoint already exists, the endpoint is reused.
// This call is idempotent
func ProvisionEndpoint(epName string, expectedNetworkId string, containerID string, makeEndpoint EndpointMakerFunc) (*hcsshim.HNSEndpoint, error) {
	// check if endpoint already exists
	createEndpoint := true
	hnsEndpoint, err := hcsshim.GetHNSEndpointByName(epName)
	if hnsEndpoint != nil && hnsEndpoint.VirtualNetwork == expectedNetworkId {
		createEndpoint = false
	}

	if createEndpoint {
		if hnsEndpoint != nil {
			if _, err = hnsEndpoint.Delete(); err != nil {
				return nil, errors.Annotate(err, "failed to delete the stale HNSEndpoint")
			}
		}

		if hnsEndpoint, err = makeEndpoint(); err != nil {
			return nil, errors.Annotate(err, "failed to make a new HNSEndpoint")
		}

		if hnsEndpoint, err = hnsEndpoint.Create(); err != nil {
			return nil, errors.Annotate(err, "failed to create the new HNSEndpoint")
		}

	}

	// hot attach
	if err := hcsshim.HotAttachEndpoint(containerID, hnsEndpoint.Id); err != nil {
		if hcsshim.ErrComputeSystemDoesNotExist == err {
			return hnsEndpoint, nil
		}

		return nil, err
	}

	return hnsEndpoint, nil
}

// ConstructResult constructs the CNI result for the endpoint
func ConstructResult(hnsNetwork *hcsshim.HNSNetwork, hnsEndpoint *hcsshim.HNSEndpoint) (*current.Result, error) {
	resultInterface := &current.Interface{
		Name: hnsEndpoint.Name,
		Mac:  hnsEndpoint.MacAddress,
	}
	_, ipSubnet, err := net.ParseCIDR(hnsNetwork.Subnets[0].AddressPrefix)
	if err != nil {
		return nil, errors.Annotatef(err, "failed to parse CIDR from %s", hnsNetwork.Subnets[0].AddressPrefix)
	}

	var ipVersion string
	if ipv4 := hnsEndpoint.IPAddress.To4(); ipv4 != nil {
		ipVersion = "4"
	} else if ipv6 := hnsEndpoint.IPAddress.To16(); ipv6 != nil {
		ipVersion = "6"
	} else {
		return nil, fmt.Errorf("IPAddress of HNSEndpoint %s isn't a valid ipv4 or ipv6 Address", hnsEndpoint.Name)
	}

	resultIPConfig := &current.IPConfig{
		Version: ipVersion,
		Address: net.IPNet{
			IP:   hnsEndpoint.IPAddress,
			Mask: ipSubnet.Mask},
		Gateway: net.ParseIP(hnsEndpoint.GatewayAddress),
	}
	result := &current.Result{}
	result.Interfaces = []*current.Interface{resultInterface}
	result.IPs = []*current.IPConfig{resultIPConfig}

	return result, nil
}
