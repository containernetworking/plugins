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

package main

import (
	"encoding/json"
	"fmt"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/cni/pkg/types/current"
	"github.com/containernetworking/cni/pkg/version"
	"github.com/containernetworking/plugins/pkg/firewalld"

	"github.com/godbus/dbus"
)

const (
	defaultZone = "trusted"
)

type firewalldConf struct {
	types.NetConf
	Zone          string                  `json:"zone,omitempty"`
	RawPrevResult *map[string]interface{} `json:"prevResult"`
	PrevResult    *current.Result         `json:"-"`
}

func parseConfig(stdin []byte) (*firewalldConf, error) {
	conf := firewalldConf{}

	if err := json.Unmarshal(stdin, &conf); err != nil {
		return nil, fmt.Errorf("failed to parsse network configuration: %v", err)
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
	}

	if conf.Zone == "" {
		conf.Zone = defaultZone
	}

	return &conf, nil
}

func cmdAdd(args *skel.CmdArgs) error {
	conf, err := parseConfig(args.StdinData)
	if err != nil {
		return fmt.Errorf("failed to parse config: %v", err)
	}

	if conf.PrevResult == nil {
		return fmt.Errorf("must be called as chained plugin")
	}

	conn, err := dbus.SystemBus()
	if err != nil {
		return err
	}

	for _, ip := range conf.PrevResult.IPs {
		if err := firewalld.AddSourceToZone(conn, ip.Address.IP, conf.Zone); err != nil {
			return fmt.Errorf("failed to add the address %v to %v zone: %v", ip.Address.IP, conf.Zone, err)
		}
	}

	return types.PrintResult(conf.PrevResult, conf.CNIVersion)
}

func cmdDel(args *skel.CmdArgs) error {
	// TODO(mrostecki): Currently, CNI plugins are not returning the result on DEL
	// command, so there is no way to get an IP address we should remove from zone.
	// Te remove IP addresses from firewalld gracefully, we need to return results
	// in DEL commands in all plugins.
	return nil
}

func main() {
	skel.PluginMain(cmdAdd, cmdDel, version.All)
}
