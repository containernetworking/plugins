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
	"fmt"
	"net"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/cni/pkg/types/current"
	"github.com/containernetworking/cni/pkg/version"
	"github.com/containernetworking/plugins/pkg/ns"
)

// FirewallNetConf represents the firewall configuration.
type FirewallNetConf struct {
	types.NetConf

	// Backend is the firewall type to add rules to.  Allowed values are
	// 'iptables' and 'firewalld'.
	Backend string `json:"backend"`

	// IptablesAdminChainName is an optional name to use instead of the default
	// admin rules override chain name that includes the interface name.
	IptablesAdminChainName string `json:"iptablesAdminChainName,omitempty"`

	// FirewalldZone is an optional firewalld zone to place the interface into.  If
	// the firewalld backend is used but the zone is not given, it defaults
	// to 'trusted'
	FirewalldZone string `json:"firewalldZone,omitempty"`

	RawPrevResult map[string]interface{} `json:"prevResult,omitempty"`
	PrevResult    *current.Result        `json:"-"`
}

type FirewallBackend interface {
	Add(*FirewallNetConf) error
	Del(*FirewallNetConf) error
}

func ipString(ip net.IPNet) string {
	if ip.IP.To4() == nil {
		return ip.IP.String() + "/128"
	}
	return ip.IP.String() + "/32"
}

func parseConf(data []byte) (*FirewallNetConf, error) {
	conf := FirewallNetConf{}
	if err := json.Unmarshal(data, &conf); err != nil {
		return nil, fmt.Errorf("failed to load netconf: %v", err)
	}

	// Default the firewalld zone to trusted
	if conf.FirewalldZone == "" {
		conf.FirewalldZone = "trusted"
	}

	// Parse previous result.
	if conf.RawPrevResult == nil {
		return nil, fmt.Errorf("missing prevResult from earlier plugin")
	}

	resultBytes, err := json.Marshal(conf.RawPrevResult)
	if err != nil {
		return nil, fmt.Errorf("could not serialize prevResult: %v", err)
	}
	res, err := version.NewResult(conf.CNIVersion, resultBytes)
	if err != nil {
		return nil, fmt.Errorf("could not parse prevResult: %v", err)
	}
	conf.RawPrevResult = nil
	conf.PrevResult, err = current.NewResultFromResult(res)
	if err != nil {
		return nil, fmt.Errorf("could not convert result to current version: %v", err)
	}

	return &conf, nil
}

func getBackend(conf *FirewallNetConf) (FirewallBackend, error) {
	switch conf.Backend {
	case "iptables":
		return newIptablesBackend(conf)
	case "firewalld":
		return newFirewalldBackend(conf)
	}

	// Default to firewalld if it's running
	if isFirewalldRunning() {
		return newFirewalldBackend(conf)
	}

	// Otherwise iptables
	return newIptablesBackend(conf)
}

func cmdAdd(args *skel.CmdArgs) error {
	conf, err := parseConf(args.StdinData)
	if err != nil {
		return err
	}

	backend, err := getBackend(conf)
	if err != nil {
		return err
	}

	if err := backend.Add(conf); err != nil {
		return err
	}

	result := conf.PrevResult
	if result == nil {
		result = &current.Result{}
	}
	return types.PrintResult(result, conf.CNIVersion)
}

func cmdDel(args *skel.CmdArgs) error {
	conf, err := parseConf(args.StdinData)
	if err != nil {
		return err
	}

	backend, err := getBackend(conf)
	if err != nil {
		return err
	}

	// Tolerate errors if the container namespace has been torn down already
	containerNS, err := ns.GetNS(args.Netns)
	if err == nil {
		defer containerNS.Close()
	}

	// Runtime errors are ignored
	if err := backend.Del(conf); err != nil {
		return err
	}

	return nil
}

func main() {
	skel.PluginMain(cmdAdd, cmdDel, version.All)
}
