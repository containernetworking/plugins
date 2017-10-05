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

// This is a "meta-plugin". It reads in its own netconf, combines it with
// the data from flannel generated subnet file and then invokes a plugin
// like bridge or ipvlan to do the real work.

package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/containernetworking/cni/pkg/invoke"
	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/cni/pkg/version"
	"math/big"
)

const (
	defaultSubnetFile = "/run/flannel/subnet.env"
	defaultDataDir    = "/var/lib/cni/flannel"
)

type NetConf struct {
	types.NetConf
	SubnetFile string                 `json:"subnetFile"`
	DataDir    string                 `json:"dataDir"`
	Delegate   map[string]interface{} `json:"delegate"`
}

type subnetEnv struct {
	nw     *net.IPNet
	sn     *net.IPNet
	mtu    *uint
	ipmasq *bool
}

func (se *subnetEnv) missing() string {
	m := []string{}

	if se.nw == nil {
		m = append(m, "FLANNEL_NETWORK")
	}
	if se.sn == nil {
		m = append(m, "FLANNEL_SUBNET")
	}
	if se.mtu == nil {
		m = append(m, "FLANNEL_MTU")
	}
	if se.ipmasq == nil {
		m = append(m, "FLANNEL_IPMASQ")
	}
	return strings.Join(m, ", ")
}

func loadFlannelNetConf(bytes []byte) (*NetConf, error) {
	n := &NetConf{
		SubnetFile: defaultSubnetFile,
		DataDir:    defaultDataDir,
	}
	if err := json.Unmarshal(bytes, n); err != nil {
		return nil, fmt.Errorf("failed to load netconf: %v", err)
	}
	return n, nil
}

func loadFlannelSubnetEnv(fn string) (*subnetEnv, error) {
	f, err := os.Open(fn)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	se := &subnetEnv{}

	s := bufio.NewScanner(f)
	for s.Scan() {
		parts := strings.SplitN(s.Text(), "=", 2)
		switch parts[0] {
		case "FLANNEL_NETWORK":
			_, se.nw, err = net.ParseCIDR(parts[1])
			if err != nil {
				return nil, err
			}

		case "FLANNEL_SUBNET":
			_, se.sn, err = net.ParseCIDR(parts[1])
			if err != nil {
				return nil, err
			}

		case "FLANNEL_MTU":
			mtu, err := strconv.ParseUint(parts[1], 10, 32)
			if err != nil {
				return nil, err
			}
			se.mtu = new(uint)
			*se.mtu = uint(mtu)

		case "FLANNEL_IPMASQ":
			ipmasq := parts[1] == "true"
			se.ipmasq = &ipmasq
		}
	}
	if err := s.Err(); err != nil {
		return nil, err
	}

	if m := se.missing(); m != "" {
		return nil, fmt.Errorf("%v is missing %v", fn, m)
	}

	return se, nil
}

func saveScratchNetConf(containerID, dataDir string, netconf []byte) error {
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		return err
	}
	path := filepath.Join(dataDir, containerID)
	return ioutil.WriteFile(path, netconf, 0600)
}

func consumeScratchNetConf(containerID, dataDir string) ([]byte, error) {
	path := filepath.Join(dataDir, containerID)
	// Ignore errors when removing - Per spec safe to continue during DEL
	defer os.Remove(path)

	return ioutil.ReadFile(path)
}

func delegateAdd(cid, dataDir string, netconf map[string]interface{}) error {
	netconfBytes, err := json.Marshal(netconf)
	if err != nil {
		return fmt.Errorf("error serializing delegate netconf: %v", err)
	}

	// save the rendered netconf for cmdDel
	if err = saveScratchNetConf(cid, dataDir, netconfBytes); err != nil {
		return err
	}

	result, err := invoke.DelegateAdd(netconf["type"].(string), netconfBytes)
	if err != nil {
		return err
	}

	return result.Print()
}

func hasKey(m map[string]interface{}, k string) bool {
	_, ok := m[k]
	return ok
}

func isString(i interface{}) bool {
	_, ok := i.(string)
	return ok
}

func cmdAdd(args *skel.CmdArgs) error {
	n, err := loadFlannelNetConf(args.StdinData)
	if err != nil {
		return err
	}

	fenv, err := loadFlannelSubnetEnv(n.SubnetFile)
	if err != nil {
		return err
	}

	if n.Delegate == nil {
		n.Delegate = make(map[string]interface{})
	} else {
		if hasKey(n.Delegate, "type") && !isString(n.Delegate["type"]) {
			return fmt.Errorf("'delegate' dictionary, if present, must have (string) 'type' field")
		}
		if hasKey(n.Delegate, "name") {
			return fmt.Errorf("'delegate' dictionary must not have 'name' field, it'll be set by flannel")
		}
		if hasKey(n.Delegate, "ipam") {
			return fmt.Errorf("'delegate' dictionary must not have 'ipam' field, it'll be set by flannel")
		}
	}

	if runtime.GOOS == "windows" {
		return cmdAddWindows(args.ContainerID, n, fenv)
	}

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

	n.Delegate["ipam"] = map[string]interface{}{
		"type":   "host-local",
		"subnet": fenv.sn.String(),
		"routes": []types.Route{
			types.Route{
				Dst: *fenv.nw,
			},
		},
	}

	return delegateAdd(args.ContainerID, n.DataDir, n.Delegate)
}

func cmdAddWindows(containerID string, n *NetConf, fenv *subnetEnv) error {

	n.Delegate["name"] = n.Name

	if !hasKey(n.Delegate, "type") {
		n.Delegate["type"] = "wincni.exe"
	}

	updateOutboundNat(n.Delegate, fenv)

	n.Delegate["cniVersion"] = "0.2.0"
	if n.CNIVersion != "" {
		n.Delegate["cniVersion"] = n.CNIVersion
	}

	// for now get Windows HNS to do IPAM
	n.Delegate["ipam"] = map[string]interface{}{
		"subnet": fenv.sn.String(),
		"routes": []interface{}{
			map[string]interface{}{
				"GW": calcGatewayIPforWindows(fenv.sn),
			},
		},
	}

	return delegateAdd(containerID, n.DataDir, n.Delegate)
}

func updateOutboundNat(delegate map[string]interface{}, fenv *subnetEnv) {
	if !*fenv.ipmasq {
		return
	}

	if !hasKey(delegate, "AdditionalArgs") {
		delegate["AdditionalArgs"] = []interface{}{}
	}
	addlArgs := delegate["AdditionalArgs"].([]interface{})
	nwToNat := fenv.nw.String()
	for _, policy := range addlArgs {
		pt := policy.(map[string]interface{})
		if !hasKey(pt, "Value") {
			continue
		}

		pv, ok := pt["Value"].(map[string]interface{})
		if !ok || !hasKey(pv, "Type") {
			continue
		}

		if !strings.EqualFold(pv["Type"].(string), "OutBoundNAT") {
			continue
		}

		if !hasKey(pv, "ExceptionList") {
			// add the exception since there weren't any
			pv["ExceptionList"] = []interface{}{nwToNat}
			return
		}

		nets := pv["ExceptionList"].([]interface{})
		for _, net := range nets {
			if net.(string) == nwToNat {
				// found it - do nothing
				return
			}
		}

		// its not in the list of exceptions, add it and we're done
		pv["ExceptionList"] = append(nets, nwToNat)
		return
	}

	// didn't find the policy, add it
	natEntry := map[string]interface{}{
		"Name": "EndpointPolicy",
		"Value": map[string]interface{}{
			"Type": "OutBoundNAT",
			"ExceptionList": []interface{}{
				nwToNat,
			},
		},
	}
	delegate["AdditionalArgs"] = append(addlArgs, natEntry)
}

func calcGatewayIPforWindows(ipn *net.IPNet) net.IP {
	// HNS currently requires x.x.x.2
	nid := ipn.IP.Mask(ipn.Mask)
	nid[len(nid)-1] += 2
	return nid
}

func ipToInt(ip net.IP) *big.Int {
	if v := ip.To4(); v != nil {
		return big.NewInt(0).SetBytes(v)
	}
	return big.NewInt(0).SetBytes(ip.To16())
}

func intToIP(i *big.Int) net.IP {
	return net.IP(i.Bytes())
}

func cmdDel(args *skel.CmdArgs) error {
	nc, err := loadFlannelNetConf(args.StdinData)
	if err != nil {
		return err
	}

	netconfBytes, err := consumeScratchNetConf(args.ContainerID, nc.DataDir)
	if err != nil {
		if os.IsNotExist(err) {
			// Per spec should ignore error if resources are missing / already removed
			return nil
		}
		return err
	}

	n := &types.NetConf{}
	if err = json.Unmarshal(netconfBytes, n); err != nil {
		return fmt.Errorf("failed to parse netconf: %v", err)
	}

	return invoke.DelegateDel(n.Type, netconfBytes)
}

func main() {
	skel.PluginMain(cmdAdd, cmdDel, version.All)
}
