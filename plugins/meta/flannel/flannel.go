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

	"encoding/binary"
	"errors"
	"github.com/containernetworking/cni/pkg/invoke"
	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/cni/pkg/version"
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

	if n.CNIVersion != "" {
		n.Delegate["cniVersion"] = n.CNIVersion
	}

	n.Delegate["name"] = n.Name

	if runtime.GOOS == "windows" {
		if err := prepareAddWindows(n, fenv); err != nil {
			return err
		}
	} else {
		prepareAddLinux(n, fenv)
	}

	return delegateAdd(args.ContainerID, n.DataDir, n.Delegate)
}

func prepareAddLinux(n *NetConf, fenv *subnetEnv) {

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

	n.Delegate["ipam"] = map[string]interface{}{
		"type":   "host-local",
		"subnet": fenv.sn.String(),
		"routes": []types.Route{
			types.Route{
				Dst: *fenv.nw,
			},
		},
	}
}

func prepareAddWindows(n *NetConf, fenv *subnetEnv) error {

	if !hasKey(n.Delegate, "type") {
		n.Delegate["type"] = "wincni.exe"
	}

	updateOutboundNat(n.Delegate, fenv)

	backendType := "host-gw"
	if hasKey(n.Delegate, "backendType") {
		backendType = n.Delegate["backendType"].(string)
	}

	switch backendType {
	case "host-gw":
		// let HNS do IPAM for hostgw (L2 bridge) mode
		gw := fenv.sn.IP.Mask(fenv.sn.Mask)
		gw[len(gw)-1] += 2

		n.Delegate["ipam"] = map[string]interface{}{
			"subnet": fenv.sn.String(),
			"routes": []interface{}{
				map[string]interface{}{
					"GW": gw.String(),
				},
			},
		}
	case "vxlan":
		// for vxlan (Overlay) mode the gw is on the cluster CIDR
		gw := fenv.nw.IP.Mask(fenv.nw.Mask)
		gw[len(gw)-1] += 1

		// but restrict allocation to the node's pod CIDR
		rs := fenv.sn.IP.Mask(fenv.sn.Mask).To4()
		rs[len(rs)-1] += 2
		re, err := lastAddr(fenv.sn)
		if err != nil {
			return err
		}
		re[len(re)-1] -= 1
		n.Delegate["ipam"] = map[string]interface{}{
			"type":       "host-local",
			"subnet":     fenv.nw.String(),
			"rangeStart": rs.String(),
			"rangeEnd":   re.String(),
			"gateway":    gw.String(),
		}

	default:
		return fmt.Errorf("backendType [%v] is not supported on windows", backendType)
	}

	return nil
}

// https://stackoverflow.com/questions/36166791/how-to-get-broadcast-address-of-ipv4-net-ipnet
func lastAddr(n *net.IPNet) (net.IP, error) { // works when the n is a prefix, otherwise...
	if n.IP.To4() == nil {
		return net.IP{}, errors.New("does not support IPv6 addresses.")
	}
	ip := make(net.IP, len(n.IP.To4()))
	binary.BigEndian.PutUint32(ip, binary.BigEndian.Uint32(n.IP.To4())|^binary.BigEndian.Uint32(net.IP(n.Mask).To4()))
	return ip, nil
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
