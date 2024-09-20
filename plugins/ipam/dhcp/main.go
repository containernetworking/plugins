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
	"flag"
	"fmt"
	"log"
	"net/rpc"
	"os"
	"path/filepath"
	"time"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	current "github.com/containernetworking/cni/pkg/types/100"
	"github.com/containernetworking/cni/pkg/version"
	bv "github.com/containernetworking/plugins/pkg/utils/buildversion"
)

const defaultSocketPath = "/run/cni/dhcp.sock"

// The top-level network config - IPAM plugins are passed the full configuration
// of the calling plugin, not just the IPAM section.
type NetConf struct {
	types.NetConf
	IPAM *IPAMConfig `json:"ipam"`
}

type IPAMConfig struct {
	types.IPAM
	DaemonSocketPath string `json:"daemonSocketPath"`
	// When requesting IP from DHCP server, carry these options for management purpose.
	// Some fields have default values, and can be override by setting a new option with the same name at here.
	ProvideOptions []ProvideOption `json:"provide"`
	// When requesting IP from DHCP server, claiming these options are necessary. Options are necessary unless `optional`
	// is set to `false`.
	// To override default requesting fields, set `skipDefault` to `false`.
	// If an field is not optional, but the server failed to provide it, error will be raised.
	RequestOptions []RequestOption `json:"request"`
	// The metric of routes
	Priority int `json:"priority,omitempty"`
}

// DHCPOption represents a DHCP option. It can be a number, or a string defined in manual dhcp-options(5).
// Note that not all DHCP options are supported at all time. Error will be raised if unsupported options are used.
type DHCPOption string

type ProvideOption struct {
	Option DHCPOption `json:"option"`

	Value           string `json:"value"`
	ValueFromCNIArg string `json:"fromArg"`
}

type RequestOption struct {
	SkipDefault bool `json:"skipDefault"`

	Option DHCPOption `json:"option"`
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "daemon" {
		var pidfilePath string
		var hostPrefix string
		var socketPath string
		var broadcast bool
		var timeout time.Duration
		var resendMax time.Duration
		var resendTimeout time.Duration
		daemonFlags := flag.NewFlagSet("daemon", flag.ExitOnError)
		daemonFlags.StringVar(&pidfilePath, "pidfile", "", "optional path to write daemon PID to")
		daemonFlags.StringVar(&hostPrefix, "hostprefix", "", "optional prefix to host root")
		daemonFlags.StringVar(&socketPath, "socketpath", "", "optional dhcp server socketpath")
		daemonFlags.BoolVar(&broadcast, "broadcast", false, "broadcast DHCP leases")
		daemonFlags.DurationVar(&timeout, "timeout", 10*time.Second, "optional dhcp client timeout duration for each request")
		daemonFlags.DurationVar(&resendMax, "resendmax", resendDelayMax, "optional dhcp client max resend delay between requests")
		daemonFlags.DurationVar(&resendTimeout, "resendtimeout", defaultResendTimeout, "optional dhcp client resend timeout, no more retries after this timeout")
		daemonFlags.Parse(os.Args[2:])

		if socketPath == "" {
			socketPath = defaultSocketPath
		}

		if err := runDaemon(pidfilePath, hostPrefix, socketPath, timeout, resendMax, resendTimeout, broadcast); err != nil {
			log.Print(err.Error())
			os.Exit(1)
		}
	} else {
		skel.PluginMainFuncs(skel.CNIFuncs{
			Add:   cmdAdd,
			Check: cmdCheck,
			Del:   cmdDel,
			/* FIXME GC */
			/* FIXME Status */
		}, version.All, bv.BuildString("dhcp"))
	}
}

func cmdAdd(args *skel.CmdArgs) error {
	// Plugin must return result in same version as specified in netconf
	versionDecoder := &version.ConfigDecoder{}
	confVersion, err := versionDecoder.Decode(args.StdinData)
	if err != nil {
		return err
	}

	result := &current.Result{CNIVersion: current.ImplementedSpecVersion}
	if err := rpcCall("DHCP.Allocate", args, result); err != nil {
		return err
	}

	return types.PrintResult(result, confVersion)
}

func cmdDel(args *skel.CmdArgs) error {
	result := struct{}{}
	return rpcCall("DHCP.Release", args, &result)
}

func cmdCheck(args *skel.CmdArgs) error {
	// Plugin must return result in same version as specified in netconf
	versionDecoder := &version.ConfigDecoder{}
	// confVersion, err := versionDecoder.Decode(args.StdinData)
	_, err := versionDecoder.Decode(args.StdinData)
	if err != nil {
		return err
	}

	result := &current.Result{CNIVersion: current.ImplementedSpecVersion}
	return rpcCall("DHCP.Allocate", args, result)
}

func getSocketPath(stdinData []byte) (string, error) {
	conf := NetConf{}
	if err := json.Unmarshal(stdinData, &conf); err != nil {
		return "", fmt.Errorf("error parsing socket path conf: %v", err)
	}
	if conf.IPAM.DaemonSocketPath == "" {
		return defaultSocketPath, nil
	}
	return conf.IPAM.DaemonSocketPath, nil
}

func rpcCall(method string, args *skel.CmdArgs, result interface{}) error {
	socketPath, err := getSocketPath(args.StdinData)
	if err != nil {
		return fmt.Errorf("error obtaining socketPath: %v", err)
	}

	client, err := rpc.DialHTTP("unix", socketPath)
	if err != nil {
		return fmt.Errorf("error dialing DHCP daemon: %v", err)
	}

	// The daemon may be running under a different working dir
	// so make sure the netns path is absolute.
	netns, err := filepath.Abs(args.Netns)
	if err != nil {
		return fmt.Errorf("failed to make %q an absolute path: %v", args.Netns, err)
	}
	args.Netns = netns

	err = client.Call(method, args, result)
	if err != nil {
		return fmt.Errorf("error calling %v: %v", method, err)
	}

	return nil
}
