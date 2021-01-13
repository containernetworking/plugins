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

// This is a "meta-plugin". It reads in its own netconf, combines it with
// the data from flannel generated subnet file and then invokes a plugin
// like bridge or ipvlan to do the real work.

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/containernetworking/cni/pkg/invoke"
	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
)

// Return IPAM section for Delegate using input IPAM if present and replacing
// or complementing as needed.
func getDelegateIPAM(n *NetConf, fenv *subnetEnv) (map[string]interface{}, error) {
	ipam := n.IPAM
	if ipam == nil {
		ipam = map[string]interface{}{}
	}

	if !hasKey(ipam, "type") {
		ipam["type"] = "host-local"
	}

	var rangesSlice [][]map[string]interface{}

	if fenv.sn != nil && fenv.sn.String() != "" {
		rangesSlice = append(rangesSlice, []map[string]interface{}{
			{"subnet": fenv.sn.String()},
		},
		)
	}
	if fenv.ip6Sn != nil && fenv.ip6Sn.String() != "" {
		rangesSlice = append(rangesSlice, []map[string]interface{}{
			{"subnet": fenv.ip6Sn.String()},
		},
		)
	}
	ipam["ranges"] = rangesSlice

	rtes, err := getIPAMRoutes(n)
	if err != nil {
		return nil, fmt.Errorf("failed to read IPAM routes: %w", err)
	}
	if fenv.nw != nil {
		rtes = append(rtes, types.Route{Dst: *fenv.nw})
	}
	if fenv.ip6Nw != nil {
		rtes = append(rtes, types.Route{Dst: *fenv.ip6Nw})
	}
	ipam["routes"] = rtes

	return ipam, nil
}

func doCmdAdd(args *skel.CmdArgs, n *NetConf, fenv *subnetEnv) error {
	n.Delegate["name"] = n.Name

	if !hasKey(n.Delegate, "type") {
		n.Delegate["type"] = "bridge"
	}

	if !hasKey(n.Delegate, "ipMasq") {
		// if flannel is not doing ipmasq, we should
		ipmasq := !*fenv.ipmasq
		n.Delegate["ipMasq"] = ipmasq
	}

	if !hasKey(n.Delegate, "mtu") {
		mtu := fenv.mtu
		n.Delegate["mtu"] = mtu
	}

	if n.Delegate["type"].(string) == "bridge" {
		if !hasKey(n.Delegate, "isGateway") {
			n.Delegate["isGateway"] = true
		}
	}
	if n.CNIVersion != "" {
		n.Delegate["cniVersion"] = n.CNIVersion
	}

	ipam, err := getDelegateIPAM(n, fenv)
	if err != nil {
		return fmt.Errorf("failed to assemble Delegate IPAM: %w", err)
	}
	n.Delegate["ipam"] = ipam

	return delegateAdd(args.ContainerID, n.DataDir, n.Delegate)
}

func doCmdDel(args *skel.CmdArgs, n *NetConf) (err error) {
	cleanup, netConfBytes, err := consumeScratchNetConf(args.ContainerID, n.DataDir)
	if err != nil {
		if os.IsNotExist(err) {
			// Per spec should ignore error if resources are missing / already removed
			return nil
		}
		return err
	}

	// cleanup will work when no error happens
	defer func() {
		cleanup(err)
	}()

	nc := &types.NetConf{}
	if err = json.Unmarshal(netConfBytes, nc); err != nil {
		return fmt.Errorf("failed to parse netconf: %v", err)
	}

	return invoke.DelegateDel(context.TODO(), nc.Type, netConfBytes, nil)
}
