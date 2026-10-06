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
	"net"
	"reflect"
	"testing"

	dhcp4 "github.com/insomniacslk/dhcp/dhcpv4"

	"github.com/containernetworking/cni/pkg/types"
)

func validateRoutes(t *testing.T, routes []*types.Route) {
	expected := []*types.Route{
		{
			Dst: net.IPNet{
				IP:   net.IPv4(10, 0, 0, 0),
				Mask: net.CIDRMask(8, 32),
			},
			GW: net.IPv4(10, 1, 2, 3),
		},
		{
			Dst: net.IPNet{
				IP:   net.IPv4(192, 168, 1, 0),
				Mask: net.CIDRMask(24, 32),
			},
			GW: net.IPv4(192, 168, 2, 3),
		},
	}

	if len(routes) != len(expected) {
		t.Fatalf("wrong length slice; expected %v, got %v", len(expected), len(routes))
	}

	for i := 0; i < len(routes); i++ {
		a := routes[i]
		e := expected[i]

		if a.Dst.String() != e.Dst.String() {
			t.Errorf("route.Dst mismatch: expected %v, got %v", e.Dst, a.Dst)
		}

		if !a.GW.Equal(e.GW) {
			t.Errorf("route.GW mismatch: expected %v, got %v", e.GW, a.GW)
		}
	}
}

func TestParseRoutes(t *testing.T) {
	data := []byte{10, 0, 0, 0, 10, 1, 2, 3, 192, 168, 1, 0, 192, 168, 2, 3}
	routes := parseRoutes(data)

	validateRoutes(t, routes)
}

func TestParseOptionName(t *testing.T) {
	tests := []struct {
		name    string
		option  string
		want    dhcp4.OptionCode
		wantErr bool
	}{
		{
			"hostname", "host-name", dhcp4.OptionHostName, false,
		},
		{
			"hostname in number", "12", dhcp4.GenericOptionCode(12), false,
		},
		{
			"random string", "doNotparseMe", dhcp4.OptionPad, true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseOptionName(tt.option)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseOptionName() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("parseOptionName() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseSuppress(t *testing.T) {
	tests := []struct {
		name        string
		items       []string
		wantGateway bool
		wantErr     bool
	}{
		{name: "nil", items: nil, wantGateway: false},
		{name: "empty", items: []string{}, wantGateway: false},
		{name: "gateway", items: []string{"gateway"}, wantGateway: true},
		{name: "unknown", items: []string{"routes"}, wantErr: true},
		{name: "gateway and unknown", items: []string{"gateway", "nope"}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseSuppress(tt.items)
			if (err != nil) != tt.wantErr {
				t.Fatalf("parseSuppress() error = %v, wantErr %v", err, tt.wantErr)
			}
			if got != tt.wantGateway {
				t.Errorf("parseSuppress() = %v, want %v", got, tt.wantGateway)
			}
		})
	}
}

func TestIsDefaultRoute(t *testing.T) {
	_, def4, err := net.ParseCIDR("0.0.0.0/0")
	if err != nil {
		t.Fatal(err)
	}
	_, def6, err := net.ParseCIDR("::/0")
	if err != nil {
		t.Fatal(err)
	}
	_, nonDef, err := net.ParseCIDR("10.0.0.0/8")
	if err != nil {
		t.Fatal(err)
	}

	if !isDefaultRoute(*def4) {
		t.Errorf("expected 0.0.0.0/0 to be default")
	}
	if !isDefaultRoute(*def6) {
		t.Errorf("expected ::/0 to be default")
	}
	if isDefaultRoute(*nonDef) {
		t.Errorf("expected 10.0.0.0/8 not to be default")
	}
}

func TestFilterDefaultRoutes(t *testing.T) {
	_, def4, err := net.ParseCIDR("0.0.0.0/0")
	if err != nil {
		t.Fatal(err)
	}
	_, lan, err := net.ParseCIDR("10.0.0.0/8")
	if err != nil {
		t.Fatal(err)
	}

	routes := []*types.Route{
		{Dst: *def4, GW: net.IPv4(192, 168, 1, 1)},
		{Dst: *lan, GW: net.IPv4(192, 168, 1, 1)},
		nil,
	}
	got := filterDefaultRoutes(routes)
	if len(got) != 1 {
		t.Fatalf("expected 1 route, got %d", len(got))
	}
	if got[0].Dst.String() != "10.0.0.0/8" {
		t.Errorf("unexpected route: %v", got[0].Dst)
	}

	if filterDefaultRoutes(nil) != nil {
		t.Errorf("nil input should return nil")
	}
	if len(filterDefaultRoutes([]*types.Route{})) != 0 {
		t.Errorf("empty input should return empty")
	}
}
