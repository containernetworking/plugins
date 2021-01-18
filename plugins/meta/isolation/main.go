// Copyright 2021 CNI authors
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

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/cni/pkg/types/current"
	"github.com/containernetworking/cni/pkg/version"
	"github.com/coreos/go-iptables/iptables"

	bv "github.com/containernetworking/plugins/pkg/utils/buildversion"
)

// PluginName
const PluginName = "isolation"

// PluginConf
type PluginConf struct {
	types.NetConf

	// Chained prev results
	RawPrevResult *map[string]interface{} `json:"prevResult"`
	PrevResult    *current.Result         `json:"-"`

	// Internal states
	bridgeName string
}

// parseConfig parses the supplied configuration (and prevResult) from stdin.
func parseConfig(stdin []byte) (*PluginConf, error) {
	conf := PluginConf{}

	if err := json.Unmarshal(stdin, &conf); err != nil {
		return nil, fmt.Errorf("failed to parse network configuration: %v", err)
	}

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
	} else {
		return nil, fmt.Errorf("needs to be chained with \"bridge\" plugin")
	}

	if len(conf.PrevResult.Interfaces) == 0 {
		return nil, fmt.Errorf("interface needs to be set, make sure to chain %q plugin with \"bridge\"", PluginName)
	}
	intf := conf.PrevResult.Interfaces[0]
	if intf == nil {
		return nil, fmt.Errorf("got nil interface")
	}
	conf.bridgeName = intf.Name

	if conf.bridgeName == "" {
		return nil, fmt.Errorf("got empty bridge name")
	}
	return &conf, nil
}

func hasV6(conf *PluginConf) bool {
	for _, f := range conf.PrevResult.IPs {
		if f != nil && f.Version == "6" {
			return true
		}
	}
	return false
}

func getIPTables(withV6 bool) ([]*iptables.IPTables, error) {
	ipt4, err := iptables.New()
	if err != nil {
		return nil, err
	}
	res := []*iptables.IPTables{ipt4}

	if withV6 {
		ipt6, err := iptables.NewWithProtocol(iptables.ProtocolIPv6)
		if err != nil {
			return nil, err
		}
		res = append(res, ipt6)
	}
	return res, nil
}

// cmdAdd is called for ADD requests
func cmdAdd(args *skel.CmdArgs) error {
	conf, err := parseConfig(args.StdinData)
	if err != nil {
		return err
	}

	ipts, err := getIPTables(hasV6(conf))
	if err != nil {
		return err
	}

	for _, ipt := range ipts {
		if err := setupChain(ipt, conf.bridgeName); err != nil {
			return err
		}
	}

	// Pass through the result for the next plugin
	return types.PrintResult(conf.PrevResult, conf.CNIVersion)
}

// cmdDel is called for DELETE requests
func cmdDel(args *skel.CmdArgs) error {
	conf, err := parseConfig(args.StdinData)
	if err != nil {
		return err
	}
	_ = conf

	// We can't be sure whether conf.bridgeName is still in use by other containers.
	// So we do not remove the iptable rules that are created per bridge.
	return nil
}

func main() {
	skel.PluginMain(cmdAdd, cmdCheck, cmdDel, version.All, bv.BuildString(PluginName))
}

func cmdCheck(args *skel.CmdArgs) error {
	return nil
}
