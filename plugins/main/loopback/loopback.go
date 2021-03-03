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

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"

	"github.com/vishvananda/netlink"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	current "github.com/containernetworking/cni/pkg/types/100"
	"github.com/containernetworking/cni/pkg/version"

	"github.com/containernetworking/plugins/pkg/ns"
	bv "github.com/containernetworking/plugins/pkg/utils/buildversion"
)

func parseNetConf(bytes []byte) (*types.NetConf, error) {
	conf := &types.NetConf{}
	if err := json.Unmarshal(bytes, conf); err != nil {
		return nil, fmt.Errorf("failed to parse network config: %v", err)
	}

	if conf.RawPrevResult != nil {
		if err := version.ParsePrevResult(conf); err != nil {
			return nil, fmt.Errorf("failed to parse prevResult: %v", err)
		}
		if _, err := current.NewResultFromResult(conf.PrevResult); err != nil {
			return nil, fmt.Errorf("failed to convert result to current version: %v", err)
		}
	}

	return conf, nil
}

func cmdAdd(args *skel.CmdArgs) error {
	conf, err := parseNetConf(args.StdinData)
	if err != nil {
		return err
	}

	var v4Addr, v6Addr *net.IPNet

	args.IfName = "lo" // ignore config, this only works for loopback
	err = ns.WithNetNSPath(args.Netns, func(_ ns.NetNS) error {
		link, err := netlink.LinkByName(args.IfName)
		if err != nil {
			return err // not tested
		}

		err = netlink.LinkSetUp(link)
		if err != nil {
			return err // not tested
		}

		v4Addrs, err := netlink.AddrList(link, netlink.FAMILY_V4)
		if err != nil {
			return err // not tested
		}
		if len(v4Addrs) != 0 {
			v4Addr = v4Addrs[0].IPNet
			// sanity check that this is a loopback address
			for _, addr := range v4Addrs {
				if !addr.IP.IsLoopback() {
					return fmt.Errorf("loopback interface found with non-loopback address %q", addr.IP)
				}
			}
		}

		v6Addrs, err := netlink.AddrList(link, netlink.FAMILY_V6)
		if err != nil {
			return err // not tested
		}
		if len(v6Addrs) != 0 {
			v6Addr = v6Addrs[0].IPNet
			// sanity check that this is a loopback address
			for _, addr := range v6Addrs {
				if !addr.IP.IsLoopback() {
					return fmt.Errorf("loopback interface found with non-loopback address %q", addr.IP)
				}
			}
		}

		return nil
	})
	if err != nil {
		return err // not tested
	}

	var result types.Result
	if conf.PrevResult != nil {
		// If loopback has previous result which passes from previous CNI plugin,
		// loopback should pass it transparently
		result = conf.PrevResult
	} else {
		r := &current.Result{
			CNIVersion: conf.CNIVersion,
			Interfaces: []*current.Interface{
				&current.Interface{
					Name:    args.IfName,
					Mac:     "00:00:00:00:00:00",
					Sandbox: args.Netns,
				},
			},
		}

		if v4Addr != nil {
			r.IPs = append(r.IPs, &current.IPConfig{
				Interface: current.Int(0),
				Address:   *v4Addr,
			})
		}

		if v6Addr != nil {
			r.IPs = append(r.IPs, &current.IPConfig{
				Interface: current.Int(0),
				Address:   *v6Addr,
			})
		}

		result = r
	}

	return types.PrintResult(result, conf.CNIVersion)
}

func cmdDel(args *skel.CmdArgs) error {
	if args.Netns == "" {
		return nil
	}
	args.IfName = "lo" // ignore config, this only works for loopback
	err := ns.WithNetNSPath(args.Netns, func(ns.NetNS) error {
		link, err := netlink.LinkByName(args.IfName)
		if err != nil {
			return err // not tested
		}

		err = netlink.LinkSetDown(link)
		if err != nil {
			return err // not tested
		}

		return nil
	})
	if err != nil {
		return err // not tested
	}

	return nil
}

func main() {
	skel.PluginMain(cmdAdd, cmdCheck, cmdDel, version.All, bv.BuildString("loopback"))
}

func cmdCheck(args *skel.CmdArgs) error {
	args.IfName = "lo" // ignore config, this only works for loopback

	return ns.WithNetNSPath(args.Netns, func(_ ns.NetNS) error {
		link, err := netlink.LinkByName(args.IfName)
		if err != nil {
			return err
		}

		if link.Attrs().Flags&net.FlagUp != net.FlagUp {
			return errors.New("loopback interface is down")
		}

		return nil
	})
}
