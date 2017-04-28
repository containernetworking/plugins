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
	"encoding/json"
	"fmt"
	"runtime"

	"github.com/containernetworking/cni/pkg/ns"
	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/version"
	"github.com/vishvananda/netlink"
)

type NetConf struct {
	Device string `json:"device"`
}

func init() {
	// this ensures that main runs only on main thread (thread group leader).
	// since namespace ops (unshare, setns) are done for a single thread, we
	// must ensure that the goroutine does not jump from OS thread to thread
	runtime.LockOSThread()
}

func loadConf(bytes []byte) (*NetConf, error) {
	n := &NetConf{}
	if err := json.Unmarshal(bytes, n); err != nil {
		return nil, fmt.Errorf("failed to load netconf: %v", err)
	}
	if n.Device == "" {
		return nil, fmt.Errorf(`"device" field is required. It specifies the host device to put into the pod`)
	}
	return n, nil
}

func cmdAdd(args *skel.CmdArgs) error {
	cfg, err := loadConf(args.StdinData)
	if err != nil {
		return err
	}
	containerNs, err := ns.GetNS(args.Netns)
	if err != nil {
		return fmt.Errorf("failed to open netns %q: %v", args.Netns, err)
	}
	defer containerNs.Close()
	return addLink(cfg.Device, containerNs)
}

func cmdDel(args *skel.CmdArgs) error {
	cfg, err := loadConf(args.StdinData)
	if err != nil {
		return err
	}
	containerNs, err := ns.GetNS(args.Netns)
	if err != nil {
		return fmt.Errorf("failed to open netns %q: %v", args.Netns, err)
	}
	defer containerNs.Close()
	return removeLink(cfg.Device, containerNs)
}

func addLink(name string, containerNs ns.NetNS) error {
	dev, err := netlink.LinkByName(name)
	if err != nil {
		return fmt.Errorf("failed to lookup %v: %v", name, err)
	}
	return netlink.LinkSetNsFd(dev, int(containerNs.Fd()))
}

func removeLink(name string, containerNs ns.NetNS) error {
	var dev netlink.Link
	err := containerNs.Do(func(_ ns.NetNS) error {
		d, err := netlink.LinkByName(name)
		if err != nil {
			return err
		}
		dev = d
		return nil
	})
	if err != nil {
		return err
	}
	defaultNs, err := ns.GetCurrentNS()
	if err != nil {
		return err
	}
	return netlink.LinkSetNsFd(dev, int(defaultNs.Fd()))
}

func main() {
	skel.PluginMain(cmdAdd, cmdDel, version.All)
}
