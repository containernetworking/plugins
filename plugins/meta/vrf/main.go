// Copyright 2020 CNI authors
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

	"github.com/vishvananda/netlink"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	current "github.com/containernetworking/cni/pkg/types/100"
	"github.com/containernetworking/cni/pkg/version"

	"github.com/containernetworking/plugins/pkg/ns"
	bv "github.com/containernetworking/plugins/pkg/utils/buildversion"
)

// VRFNetConf represents the vrf configuration.
type VRFNetConf struct {
	types.NetConf

	// VRFName is the name of the vrf to add the interface to.
	VRFName string `json:"vrfname"`
	// Table is the optional name of the routing table set for the vrf
	Table uint32 `json:"table"`
}

func main() {
	skel.PluginMain(cmdAdd, cmdCheck, cmdDel, version.VersionsStartingFrom("0.3.1"), bv.BuildString("vrf"))
}

func cmdAdd(args *skel.CmdArgs) error {
	conf, result, err := parseConf(args.StdinData)
	if err != nil {
		return err
	}

	if conf.PrevResult == nil {
		return fmt.Errorf("missing prevResult from earlier plugin")
	}

	err = ns.WithNetNSPath(args.Netns, func(_ ns.NetNS) error {
		vrf, err := findVRF(conf.VRFName)

		// If the user set a tableid and the vrf is already in the namespace
		// we check if the tableid is the same one already assigned to the vrf.
		if err == nil && conf.Table != 0 && vrf.Table != conf.Table {
			return fmt.Errorf("VRF %s already exist with different routing table %d", conf.VRFName, vrf.Table)
		}

		if _, ok := err.(netlink.LinkNotFoundError); ok {
			vrf, err = createVRF(conf.VRFName, conf.Table)
		}

		if err != nil {
			return err
		}

		err = addInterface(vrf, args.IfName)
		if err != nil {
			return err
		}
		return nil
	})

	if err != nil {
		return fmt.Errorf("cmdAdd failed: %v", err)
	}

	if result == nil {
		result = &current.Result{}
	}

	return types.PrintResult(result, conf.CNIVersion)
}

func cmdDel(args *skel.CmdArgs) error {
	conf, _, err := parseConf(args.StdinData)
	if err != nil {
		return err
	}
	err = ns.WithNetNSPath(args.Netns, func(_ ns.NetNS) error {
		vrf, err := findVRF(conf.VRFName)
		if _, ok := err.(netlink.LinkNotFoundError); ok {
			return nil
		}

		if err != nil {
			return err
		}

		err = resetMaster(args.IfName)
		if err != nil {
			return err
		}

		interfaces, err := assignedInterfaces(vrf)
		if err != nil {
			return err
		}

		// Meaning, we are deleting the last interface assigned to the VRF
		if len(interfaces) == 0 {
			err = netlink.LinkDel(vrf)
			if err != nil {
				return err
			}
		}
		return nil
	})

	if err != nil {
		return fmt.Errorf("cmdDel failed: %v", err)
	}
	return nil
}

func cmdCheck(args *skel.CmdArgs) error {
	conf, _, err := parseConf(args.StdinData)
	if err != nil {
		return err
	}

	// Ensure we have previous result.
	if conf.PrevResult == nil {
		return fmt.Errorf("missing prevResult from earlier plugin")
	}

	err = ns.WithNetNSPath(args.Netns, func(_ ns.NetNS) error {
		vrf, err := findVRF(conf.VRFName)
		if err != nil {
			return err
		}
		vrfInterfaces, err := assignedInterfaces(vrf)

		found := false
		for _, intf := range vrfInterfaces {
			if intf.Attrs().Name == args.IfName {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("Failed to find %s associated to vrf %s", args.IfName, conf.VRFName)
		}
		return nil
	})

	return nil
}

func parseConf(data []byte) (*VRFNetConf, *current.Result, error) {
	conf := VRFNetConf{}
	if err := json.Unmarshal(data, &conf); err != nil {
		return nil, nil, fmt.Errorf("failed to load netconf: %v", err)
	}

	if conf.VRFName == "" {
		return nil, nil, fmt.Errorf("configuration is expected to have a valid vrf name")
	}

	if conf.RawPrevResult == nil {
		// return early if there was no previous result, which is allowed for DEL calls
		return &conf, &current.Result{}, nil
	}

	// Parse previous result.
	var result *current.Result
	var err error
	if err = version.ParsePrevResult(&conf.NetConf); err != nil {
		return nil, nil, fmt.Errorf("could not parse prevResult: %v", err)
	}

	result, err = current.NewResultFromResult(conf.PrevResult)
	if err != nil {
		return nil, nil, fmt.Errorf("could not convert result to current version: %v", err)
	}

	return &conf, result, nil
}
