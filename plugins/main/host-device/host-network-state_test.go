// Copyright 2026 CNI authors
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
	"net"
	"testing"

	"github.com/vishvananda/netlink"

	current "github.com/containernetworking/cni/pkg/types/100"
)

func TestLoadConfAllowsUseInterfaceNetworkWithIPAM(t *testing.T) {
	conf := `{
		"cniVersion": "1.0.0",
		"name": "host-device",
		"type": "host-device",
		"device": "eth0",
		"useInterfaceNetwork": true,
		"ipam": { "type": "static" }
	}`
	cfg, err := loadConf([]byte(conf))
	if err != nil {
		t.Fatalf("expected loadConf to accept useInterfaceNetwork with ipam, got: %v", err)
	}
	if !cfg.UseInterfaceNetwork {
		t.Fatalf("expected UseInterfaceNetwork to be true")
	}
	if cfg.IPAM.Type != "static" {
		t.Fatalf("expected IPAM type static, got %s", cfg.IPAM.Type)
	}
}

func TestLoadConfRejectsDPDKWithUseInterfaceNetwork(t *testing.T) {
	conf := `{
		"cniVersion": "1.0.0",
		"name": "host-device",
		"type": "host-device",
		"device": "eth0",
		"useInterfaceNetwork": true
	}`
	cfg, err := loadConf([]byte(conf))
	if err != nil {
		t.Fatalf("loadConf should succeed: %v", err)
	}
	cfg.DPDKMode = true
	if !useInterfaceNetwork(cfg) || !cfg.DPDKMode {
		t.Fatalf("expected both useInterfaceNetwork and DPDKMode to be true for this test")
	}
}

func TestMergeNetworkStateIntoResult(t *testing.T) {
	tests := []struct {
		name           string
		state          *HostNetworkState
		wantIPCount    int
		wantMergedIP   string
		wantRouteCount int
		wantRouteDst   string
	}{
		{
			name: "addresses and routes",
			state: &HostNetworkState{
				Addresses: []netlink.Addr{{IPNet: mustParseCIDRPtr(t, "10.0.0.1/24")}},
				Routes: []netlink.Route{
					{Dst: mustParseIPNet(t, "20.0.0.0/24"), Gw: net.ParseIP("10.0.0.254"), Table: 254},
					{Gw: net.ParseIP("10.0.0.1")},
				},
			},
			wantIPCount:    2,
			wantMergedIP:   "10.0.0.1",
			wantRouteCount: 2,
		},
		{
			name: "routes only",
			state: &HostNetworkState{
				Routes: []netlink.Route{
					{Dst: mustParseIPNet(t, "20.0.0.0/24"), Gw: net.ParseIP("10.0.0.254"), Table: 254},
				},
			},
			wantIPCount:    1,
			wantRouteCount: 1,
			wantRouteDst:   "20.0.0.0/24",
		},
		{
			name:           "nil state",
			state:          nil,
			wantIPCount:    1,
			wantRouteCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := &current.Result{
				Interfaces: []*current.Interface{
					{Name: "net1", Sandbox: "/proc/123/ns/net"},
				},
				IPs: []*current.IPConfig{
					{
						Interface: current.Int(0),
						Address:   mustParseCIDR(t, "192.168.1.5/24"),
					},
				},
			}

			mergeNetworkStateIntoResult(result, tt.state)

			if len(result.IPs) != tt.wantIPCount {
				t.Fatalf("expected %d IPs after merge, got %d", tt.wantIPCount, len(result.IPs))
			}
			if tt.wantMergedIP != "" && result.IPs[1].Address.IP.String() != tt.wantMergedIP {
				t.Fatalf("expected merged IP %s, got %s", tt.wantMergedIP, result.IPs[1].Address.IP.String())
			}
			if len(result.Routes) != tt.wantRouteCount {
				t.Fatalf("expected %d routes after merge, got %d", tt.wantRouteCount, len(result.Routes))
			}
			if tt.wantRouteDst != "" && result.Routes[0].Dst.String() != tt.wantRouteDst {
				t.Fatalf("expected route dst %s, got %s", tt.wantRouteDst, result.Routes[0].Dst.String())
			}
		})
	}
}

func mustParseCIDR(t *testing.T, s string) net.IPNet {
	t.Helper()
	ip, ipNet, err := net.ParseCIDR(s)
	if err != nil {
		t.Fatalf("failed to parse CIDR %s: %v", s, err)
	}
	ipNet.IP = ip
	return *ipNet
}

func mustParseCIDRPtr(t *testing.T, s string) *net.IPNet {
	t.Helper()
	ip, ipNet, err := net.ParseCIDR(s)
	if err != nil {
		t.Fatalf("failed to parse CIDR %s: %v", s, err)
	}
	ipNet.IP = ip
	return ipNet
}

func mustParseIPNet(t *testing.T, s string) *net.IPNet {
	t.Helper()
	_, ipNet, err := net.ParseCIDR(s)
	if err != nil {
		t.Fatalf("failed to parse CIDR %s: %v", s, err)
	}
	return ipNet
}
