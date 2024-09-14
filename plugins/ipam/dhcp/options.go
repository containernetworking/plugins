// Copyright 2015 CNI authors
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
	"fmt"
	"net"
	"strconv"

	dhcp4 "github.com/insomniacslk/dhcp/dhcpv4"

	"github.com/containernetworking/cni/pkg/types"
)

var optionNameToID = map[string]dhcp4.OptionCode{
	"dhcp-client-identifier":  dhcp4.OptionClientIdentifier,
	"subnet-mask":             dhcp4.OptionSubnetMask,
	"routers":                 dhcp4.OptionRouter,
	"host-name":               dhcp4.OptionHostName,
	"user-class":              dhcp4.OptionUserClassInformation,
	"vendor-class-identifier": dhcp4.OptionClassIdentifier,
}

func parseOptionName(option string) (dhcp4.OptionCode, error) {
	if val, ok := optionNameToID[option]; ok {
		return val, nil
	}
	i, err := strconv.ParseUint(option, 10, 8)
	if err != nil {
		return dhcp4.OptionPad, fmt.Errorf("Can not parse option: %w", err)
	}
	return dhcp4.GenericOptionCode(i), nil
}

func classfulSubnet(sn net.IP) net.IPNet {
	return net.IPNet{
		IP:   sn,
		Mask: sn.DefaultMask(),
	}
}

func parseRoutes(opt []byte) []*types.Route {
	// StaticRoutes format: pairs of:
	// Dest = 4 bytes; Classful IP subnet
	// Router = 4 bytes; IP address of router

	routes := []*types.Route{}
	for len(opt) >= 8 {
		sn := opt[0:4]
		r := opt[4:8]
		rt := &types.Route{
			Dst: classfulSubnet(sn),
			GW:  r,
		}
		routes = append(routes, rt)
		opt = opt[8:]
	}

	return routes
}
