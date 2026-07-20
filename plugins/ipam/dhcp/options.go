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

// parseSuppress validates the suppress list and reports which known items are set.
func parseSuppress(items []string) (gateway bool, err error) {
	for _, item := range items {
		switch item {
		case suppressGateway:
			gateway = true
		default:
			return false, fmt.Errorf("unknown suppress value %q (supported: %q)", item, suppressGateway)
		}
	}
	return gateway, nil
}

// isDefaultRoute reports whether dst is a default route (prefix length 0).
func isDefaultRoute(dst net.IPNet) bool {
	ones, bits := dst.Mask.Size()
	return bits != 0 && ones == 0
}

// filterDefaultRoutes returns a copy of routes without default routes.
func filterDefaultRoutes(routes []*types.Route) []*types.Route {
	if len(routes) == 0 {
		return routes
	}
	out := make([]*types.Route, 0, len(routes))
	for _, r := range routes {
		if r == nil || isDefaultRoute(r.Dst) {
			continue
		}
		out = append(out, r)
	}
	return out
}

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
