// Copyright 2016 CNI authors
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

// This is a "meta-plugin". It reads in its own netconf, it does not create
// any network interface but just changes the network sysctl.

package main

import (
	"encoding/json"
	"net"
	"strings"

	. "github.com/onsi/ginkgo/v2"

	current "github.com/containernetworking/cni/pkg/types/100"
)

var _ = Describe("published port rule generation", func() {
	_, addr, _ := net.ParseCIDR("10.4.1.2/24")
	addr.IP = net.ParseIP("10.4.1.2")
	result := &current.Result{
		Interfaces: []*current.Interface{{Name: "br-test"}, {Name: "eth0", Sandbox: "/netns/test"}},
		IPs:        []*current.IPConfig{{Interface: current.Int(1), Address: *addr}},
	}
	for _, tc := range []struct {
		name, config string
		count        int
		invalid      bool
	}{
		{"declared mapping", `{"allowPublishedPorts":true,"ingressPolicy":"same-bridge","runtimeConfig":{"portMappings":[{"hostPort":18090,"containerPort":80,"protocol":"tcp","hostIP":"10.0.2.100"}]}}`, 2, false},
		{"opt out", `{"ingressPolicy":"same-bridge","runtimeConfig":{"portMappings":[{"hostPort":18090,"containerPort":80,"protocol":"tcp"}]}}`, 0, false},
		{"isolated policy unchanged", `{"allowPublishedPorts":true,"ingressPolicy":"isolated","runtimeConfig":{"portMappings":[{"hostPort":18090,"containerPort":80,"protocol":"tcp"}]}}`, 0, false},
		{"no published ports", `{"allowPublishedPorts":true,"ingressPolicy":"same-bridge"}`, 0, false},
		{"wrong host family", `{"allowPublishedPorts":true,"ingressPolicy":"same-bridge","runtimeConfig":{"portMappings":[{"hostPort":18090,"containerPort":80,"protocol":"tcp","hostIP":"::1"}]}}`, 0, false},
		{"invalid host port", `{"allowPublishedPorts":true,"ingressPolicy":"same-bridge","runtimeConfig":{"portMappings":[{"hostPort":0,"containerPort":80,"protocol":"tcp"}]}}`, 0, true},
		{"invalid protocol", `{"allowPublishedPorts":true,"ingressPolicy":"same-bridge","runtimeConfig":{"portMappings":[{"hostPort":18090,"containerPort":80,"protocol":"icmp"}]}}`, 0, true},
		{"invalid host IP", `{"allowPublishedPorts":true,"ingressPolicy":"same-bridge","runtimeConfig":{"portMappings":[{"hostPort":18090,"containerPort":80,"protocol":"tcp","hostIP":"invalid"}]}}`, 0, true},
	} {
		It(tc.name, func() {
			t := GinkgoT()
			conf := &FirewallNetConf{}
			if err := json.Unmarshal([]byte(tc.config), conf); err != nil {
				t.Fatal(err)
			}
			rules, err := publishedPortRules(conf, result)
			if (err != nil) != tc.invalid {
				t.Fatalf("error=%v, want invalid=%v", err, tc.invalid)
			}
			if len(rules) != tc.count {
				t.Fatalf("rules=%d, want %d", len(rules), tc.count)
			}
			if tc.count == 2 {
				for i, r := range rules {
					text := strings.Join(r.args, " ")
					for _, needed := range []string{"--ctstate DNAT", "--ctorigdstport 18090", "--ctorigdst 10.0.2.100", "-p tcp", "-j CNI-FORWARD"} {
						if !strings.Contains(text, needed) {
							t.Errorf("rule missing %q: %s", needed, text)
						}
					}
					direction := "--ctdir ORIGINAL"
					endpoint := "-d 10.4.1.2/32"
					if i == 1 {
						direction = "--ctdir REPLY"
						endpoint = "-s 10.4.1.2/32"
					}
					if !strings.Contains(text, direction) || !strings.Contains(text, endpoint) {
						t.Errorf("wrong direction/endpoint: %s", text)
					}
				}
			}
		})
	}
})

var _ = It("generates IPv6 wildcard rules without exposing gateways", func() {
	t := GinkgoT()
	conf := &FirewallNetConf{AllowPublishedPorts: true, IngressPolicy: IngressPolicySameBridge}
	conf.RuntimeConfig.PortMappings = []publishedPortMapping{{HostPort: 18090, ContainerPort: 80, Protocol: "udp", HostIP: "::"}}
	_, addr, _ := net.ParseCIDR("fd00::2/64")
	addr.IP = net.ParseIP("fd00::2")
	result := &current.Result{Interfaces: []*current.Interface{{Name: "br-test"}, {Name: "eth0", Sandbox: "/netns/test"}}, IPs: []*current.IPConfig{{Interface: current.Int(1), Address: *addr}}}
	rules, err := publishedPortRules(conf, result)
	if err != nil || len(rules) != 2 {
		t.Fatalf("rules=%v error=%v", rules, err)
	}
	for _, rule := range rules {
		text := strings.Join(rule.args, " ")
		if strings.Contains(text, "--ctorigdst ") || !strings.Contains(text, "fd00::2/128") || !strings.Contains(text, "-p udp") {
			t.Fatal(text)
		}
	}
	// A bridge/gateway address must not acquire a container's exception.
	result.IPs[0].Interface = current.Int(0)
	rules, err = publishedPortRules(conf, result)
	if err != nil || len(rules) != 0 {
		t.Fatalf("gateway exposed: %v %v", rules, err)
	}
})
