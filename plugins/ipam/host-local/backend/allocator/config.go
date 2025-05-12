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

package allocator

import (
	"encoding/json"
	"fmt"
	"net"
	"os"

	"github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/cni/pkg/version"
	"github.com/containernetworking/plugins/pkg/ip"
)

// The top-level network config - IPAM plugins are passed the full configuration
// of the calling plugin, not just the IPAM section.
type Net struct {
	Name          string      `json:"name"`
	CNIVersion    string      `json:"cniVersion"`
	IPAM          *IPAMConfig `json:"ipam"`
	RuntimeConfig struct {
		// The capability arg
		IPRanges []RangeSet `json:"ipRanges,omitempty"`
		IPs      []*ip.IP   `json:"ips,omitempty"`
	} `json:"runtimeConfig,omitempty"`
	Args *struct {
		A *IPAMArgs `json:"cni"`
	} `json:"args"`
}

// IPAMConfig represents the IP related network configuration.
// This nests Range because we initially only supported a single
// range directly, and wish to preserve backwards compatibility
type IPAMConfig struct {
	*Range
	Name          string
	Type          string         `json:"type"`
	Routes        []*types.Route `json:"routes"`
	DataDir       string         `json:"dataDir"`
	ResolvConf    string         `json:"resolvConf"`
	Ranges        []RangeSet     `json:"ranges"`
	IPArgs        []net.IP       `json:"-"` // Requested IPs from CNI_ARGS, args and capabilities
	RangeFromFile string         `json:"rangeFromFile"`
}

type IPAMEnvArgs struct {
	types.CommonArgs
	IP ip.IP `json:"ip,omitempty"`
}

type IPAMArgs struct {
	IPs []*ip.IP `json:"ips"`
}

type RangeSet []Range

type Range struct {
	RangeStart net.IP      `json:"rangeStart,omitempty"` // The first ip, inclusive
	RangeEnd   net.IP      `json:"rangeEnd,omitempty"`   // The last ip, inclusive
	Subnet     types.IPNet `json:"subnet"`
	Gateway    net.IP      `json:"gateway,omitempty"`
}

// NewIPAMConfig creates a NetworkConfig from the given network name.
func LoadIPAMConfig(bytes []byte, envArgs string) (*IPAMConfig, string, error) {
	n := Net{}
	if err := json.Unmarshal(bytes, &n); err != nil {
		return nil, "", err
	}

	if n.IPAM == nil {
		return nil, "", fmt.Errorf("IPAM config missing 'ipam' key")
	}

	// parse custom IP from env args
	if envArgs != "" {
		e := IPAMEnvArgs{}
		err := types.LoadArgs(envArgs, &e)
		if err != nil {
			return nil, "", err
		}

		if e.IP.ToIP() != nil {
			n.IPAM.IPArgs = []net.IP{e.IP.ToIP()}
		}
	}

	// parse custom IPs from CNI args in network config
	if n.Args != nil && n.Args.A != nil && len(n.Args.A.IPs) != 0 {
		for _, i := range n.Args.A.IPs {
			n.IPAM.IPArgs = append(n.IPAM.IPArgs, i.ToIP())
		}
	}

	// parse custom IPs from runtime configuration
	if len(n.RuntimeConfig.IPs) > 0 {
		for _, i := range n.RuntimeConfig.IPs {
			n.IPAM.IPArgs = append(n.IPAM.IPArgs, i.ToIP())
		}
	}

	for idx := range n.IPAM.IPArgs {
		if err := canonicalizeIP(&n.IPAM.IPArgs[idx]); err != nil {
			return nil, "", fmt.Errorf("cannot understand ip: %v", err)
		}
	}

	// If a single range (old-style config) is specified, prepend it to
	// the Ranges array
	if n.IPAM.Range != nil && n.IPAM.Range.Subnet.IP != nil {
		n.IPAM.Ranges = append([]RangeSet{{*n.IPAM.Range}}, n.IPAM.Ranges...)
	}
	n.IPAM.Range = nil

	// If a range is supplied as a runtime config, prepend it to the Ranges
	if len(n.RuntimeConfig.IPRanges) > 0 {
		n.IPAM.Ranges = append(n.RuntimeConfig.IPRanges, n.IPAM.Ranges...)
	}

	// If no ranges are configured, try to load from RangeFromFile
	if len(n.IPAM.Ranges) == 0 && n.IPAM.RangeFromFile != "" {
		fileBytes, err := os.ReadFile(n.IPAM.RangeFromFile)
		if err != nil {
			return nil, "", fmt.Errorf("failed to read rangeFromFile %q: %v", n.IPAM.RangeFromFile, err)
		}

		var singleRange Range
		if err := json.Unmarshal(fileBytes, &singleRange); err == nil {
			if singleRange.Subnet.IP != nil {
				n.IPAM.Ranges = []RangeSet{{singleRange}}
			} else {
				return nil, "", fmt.Errorf("failed to parse rangeFromFile %q as a Range", n.IPAM.RangeFromFile)
			}
		} else {
			return nil, "", fmt.Errorf("err: %v, failed to parse rangeFromFile %q as a Range", err, n.IPAM.RangeFromFile)
		}
	}

	if len(n.IPAM.Ranges) == 0 {
		return nil, "", fmt.Errorf("no IP ranges specified")
	}

	// Validate all ranges
	numV4 := 0
	numV6 := 0
	for i := range n.IPAM.Ranges {
		if err := n.IPAM.Ranges[i].Canonicalize(); err != nil {
			return nil, "", fmt.Errorf("invalid range set %d: %s", i, err)
		}

		if n.IPAM.Ranges[i][0].RangeStart.To4() != nil {
			numV4++
		} else {
			numV6++
		}
	}

	// CNI spec 0.2.0 and below supported only one v4 and v6 address
	if numV4 > 1 || numV6 > 1 {
		if ok, _ := version.GreaterThanOrEqualTo(n.CNIVersion, "0.3.0"); !ok {
			return nil, "", fmt.Errorf("CNI version %v does not support more than 1 address per family", n.CNIVersion)
		}
	}

	// Check for overlaps
	l := len(n.IPAM.Ranges)
	for i, p1 := range n.IPAM.Ranges[:l-1] {
		for j, p2 := range n.IPAM.Ranges[i+1:] {
			if p1.Overlaps(&p2) {
				return nil, "", fmt.Errorf("range set %d overlaps with %d", i, (i + j + 1))
			}
		}
	}

	// Copy net name into IPAM so not to drag Net struct around
	n.IPAM.Name = n.Name

	return n.IPAM, n.CNIVersion, nil
}
