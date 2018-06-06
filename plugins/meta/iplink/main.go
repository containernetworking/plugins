// Copyright 2018 CNI authors
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
	"github.com/vishvananda/netlink"
)

/*
 * Current support ip link command:
 + ip link set promisc <bool>
 + ip link set address <mac addr>
 + ip link set mtu <numeric>

--- syntax
{
  "name": "myiplink",
  "type": "iplink",
  "iplink": {
          "promisc": "true",
          "macaddress": "new mac addr",
          "mtu": "1454",
  }
}
*/

// TuningConf represents the network tuning configuration.
type IpLinkConf struct {
	//SysCtl        map[string]string      `json:"sysctl"`
	//IpLink        map[string]string      `json:"iplink"`
	Mac     string `json:"mac,omitempty"`
	Promisc bool   `json:"promisc,omitempty"`
	Mtu     int    `json:"mtu,omitempty"`
}

type PluginConf struct {
	types.NetConf

	RuntimeConfig struct {
		IpLinkConf *IpLinkConf `json:"iplink,omitempty"`
	} `json:"runtimeConfig,omitempty"`

	RawPrevResult map[string]interface{} `json:"prevResult,omitempty"`
	PrevResult    *current.Result        `json:"-"`

	*IpLinkConf
}

type MACEnvArgs struct {
	types.CommonArgs
	MAC types.UnmarshallableString `json:"mac,omitempty"`
}

func changeMacAddr(ifName string, newMacAddr string) error {
	addr, err := net.ParseMAC(newMacAddr)
	if err != nil {
		return fmt.Errorf("Invalid args %v for MAC addr: %v", newMacAddr, err)
	}

	link, err := netlink.LinkByName(ifName)
	if err != nil {
		return fmt.Errorf("Failed to get %s: %v", ifName, err)
	}

	err = netlink.LinkSetDown(link)
	if err != nil {
		return fmt.Errorf("Failed to set %s down: %v", ifName, err)
	}
	err = netlink.LinkSetHardwareAddr(link, addr)
	if err != nil {
		return fmt.Errorf("Failed to set %s address to %s: %v", ifName, newMacAddr, err)
	}
	return netlink.LinkSetUp(link)
}

func updateResultsMacAddr(config PluginConf, ifName string, newMacAddr string) error {
	for _, i := range config.PrevResult.Interfaces {
		if i.Name == ifName {
			i.Mac = newMacAddr
		}
	}
	return nil
}

func changePromisc(ifName string, val bool) error {
	link, err := netlink.LinkByName(ifName)
	if err != nil {
		return fmt.Errorf("Failed to get %s: %v", ifName, err)
	}

	if val {
		return netlink.SetPromiscOn(link)
	}
	return netlink.SetPromiscOff(link)
}

func changeMtu(ifName string, mtu int) error {
	link, err := netlink.LinkByName(ifName)
	if err != nil {
		return fmt.Errorf("Failed to get %s: %v", ifName, err)
	}
	return netlink.LinkSetMTU(link, mtu)
}

func parseConf(data []byte, envArgs string) (*PluginConf, error) {
	conf := PluginConf{IpLinkConf: &IpLinkConf{Promisc: false, Mtu: -1}}
	if err := json.Unmarshal(data, &conf); err != nil {
		return nil, fmt.Errorf("failed to load netconf: %v", err)
	}

	// Parse custom MAC from both env args
	if envArgs != "" {
		e := MACEnvArgs{}
		err := types.LoadArgs(envArgs, &e)
		if err != nil {
			return nil, err
		}

		if e.MAC != "" {
			conf.Mac = string(e.MAC)
		}
	}

	if conf.IpLinkConf == nil && conf.RuntimeConfig.IpLinkConf != nil {
		conf.IpLinkConf = conf.RuntimeConfig.IpLinkConf
	}

	// Parse previous result.
	if conf.RawPrevResult != nil {
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
	}

	return &conf, nil
}

func cmdAdd(args *skel.CmdArgs) error {
	conf, err := parseConf(args.StdinData, args.Args)
	if err != nil {
		return err
	}

	err = ns.WithNetNSPath(args.Netns, func(_ ns.NetNS) error {
		var err error

		if conf.Mac != "" {
			if err = changeMacAddr(args.IfName, conf.Mac); err == nil {
				err = updateResultsMacAddr(*conf, args.IfName, conf.Mac)
			}
		}

		if conf.Promisc != false {
			if err = changePromisc(args.IfName, true); err != nil {
				return err
			}
		}

		if conf.Mtu != -1 {
			if err = changeMtu(args.IfName, conf.Mtu); err != nil {
				return err
			}
		}
		return nil
	})

	if err != nil {
		return err
	}

	return types.PrintResult(conf.PrevResult, conf.CNIVersion)
}

func cmdDel(args *skel.CmdArgs) error {
	// TODO: the settings are not reverted to the previous values. Reverting the
	// settings is not useful when the whole container goes away but it could be
	// useful in scenarios where plugins are added and removed at runtime.
	return nil
}

func cmdGet(args *skel.CmdArgs) error {
	// TODO: implement
	return fmt.Errorf("not implemented")
}

func main() {
	// TODO: implement plugin version
	skel.PluginMain(cmdAdd, cmdDel, cmdGet, version.PluginSupports("0.3.0", "0.3.1", version.Current()), "TODO")
}
