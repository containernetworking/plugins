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
	"math"
	"net"

	"github.com/vishvananda/netlink"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	current "github.com/containernetworking/cni/pkg/types/100"
	"github.com/containernetworking/cni/pkg/version"
	"github.com/containernetworking/plugins/pkg/ip"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/containernetworking/plugins/pkg/utils"
	bv "github.com/containernetworking/plugins/pkg/utils/buildversion"
)

const (
	maxIfbDeviceLength = 15
	ifbDevicePrefix    = "bwp"
)

// BandwidthEntry corresponds to a single entry in the bandwidth argument,
// see CONVENTIONS.md
type BandwidthEntry struct {
	UnshapedSubnets []string `json:"unshapedSubnets"` // Ipv4/ipv6 subnets to be excluded from traffic shaping. UnshapedSubnets and ShapedSubnets parameters are mutually exlusive
	ShapedSubnets   []string `json:"shapedSubnets"`   // Ipv4/ipv6 subnets to be included in traffic shaping. UnshapedSubnets and ShapedSubnets parameters are mutually exlusive
	IngressRate     uint64   `json:"ingressRate"`     // Bandwidth rate in bps for traffic through container. 0 for no limit. If ingressRate is set, ingressBurst must also be set
	IngressBurst    uint64   `json:"ingressBurst"`    // Bandwidth burst in bits for traffic through container. 0 for no limit. If ingressBurst is set, ingressRate must also be set
	EgressRate      uint64   `json:"egressRate"`      // Bandwidth rate in bps for traffic through container. 0 for no limit. If egressRate is set, egressBurst must also be set
	EgressBurst     uint64   `json:"egressBurst"`     // Bandwidth burst in bits for traffic through container. 0 for no limit. If egressBurst is set, egressRate must also be set
}

func (bw *BandwidthEntry) isZero() bool {
	return bw.IngressBurst == 0 && bw.IngressRate == 0 && bw.EgressBurst == 0 && bw.EgressRate == 0
}

type PluginConf struct {
	types.NetConf

	RuntimeConfig struct {
		Bandwidth *BandwidthEntry `json:"bandwidth,omitempty"`
	} `json:"runtimeConfig,omitempty"`

	*BandwidthEntry
}

// parseConfig parses the supplied configuration (and prevResult) from stdin.
func parseConfig(stdin []byte) (*PluginConf, error) {
	conf := PluginConf{}

	if err := json.Unmarshal(stdin, &conf); err != nil {
		return nil, fmt.Errorf("failed to parse network configuration: %v", err)
	}

	bandwidth := getBandwidth(&conf)
	if bandwidth != nil {
		err := validateRateAndBurst(bandwidth.IngressRate, bandwidth.IngressBurst)
		if err != nil {
			return nil, err
		}
		err = validateRateAndBurst(bandwidth.EgressRate, bandwidth.EgressBurst)
		if err != nil {
			return nil, err
		}
	}

	if conf.RawPrevResult != nil {
		var err error
		if err = version.ParsePrevResult(&conf.NetConf); err != nil {
			return nil, fmt.Errorf("could not parse prevResult: %v", err)
		}

		_, err = current.NewResultFromResult(conf.PrevResult)
		if err != nil {
			return nil, fmt.Errorf("could not convert result to current version: %v", err)
		}
	}

	return &conf, nil
}

func getBandwidth(conf *PluginConf) *BandwidthEntry {
	bw := conf.BandwidthEntry
	if bw == nil && conf.RuntimeConfig.Bandwidth != nil {
		bw = conf.RuntimeConfig.Bandwidth
	}

	if bw != nil {
		if bw.UnshapedSubnets == nil {
			bw.UnshapedSubnets = make([]string, 0)
		}
		if bw.ShapedSubnets == nil {
			bw.ShapedSubnets = make([]string, 0)
		}
	}

	return bw
}

func validateRateAndBurst(rate, burst uint64) error {
	switch {
	case burst == 0 && rate != 0:
		return fmt.Errorf("if rate is set, burst must also be set")
	case rate == 0 && burst != 0:
		return fmt.Errorf("if burst is set, rate must also be set")
	case burst/8 >= math.MaxUint32:
		return fmt.Errorf("burst cannot be more than 4GB")
	}

	return nil
}

func getIfbDeviceName(networkName string, containerID string) string {
	return utils.MustFormatHashWithPrefix(maxIfbDeviceLength, ifbDevicePrefix, networkName+containerID)
}

func getMTUAndQLen(deviceName string) (int, int, error) {
	link, err := netlink.LinkByName(deviceName)
	if err != nil {
		return -1, -1, err
	}

	return link.Attrs().MTU, link.Attrs().TxQLen, nil
}

// get the veth peer of container interface in host namespace
func getHostInterface(interfaces []*current.Interface, containerIfName string, netns ns.NetNS) (*current.Interface, error) {
	if len(interfaces) == 0 {
		return nil, fmt.Errorf("no interfaces provided")
	}

	// get veth peer index of container interface
	var peerIndex int
	var err error
	_ = netns.Do(func(_ ns.NetNS) error {
		_, peerIndex, err = ip.GetVethPeerIfindex(containerIfName)
		return nil
	})
	if peerIndex <= 0 {
		return nil, fmt.Errorf("container interface %s has no veth peer: %v", containerIfName, err)
	}

	// find host interface by index
	link, err := netlink.LinkByIndex(peerIndex)
	if err != nil {
		return nil, fmt.Errorf("veth peer with index %d is not in host ns", peerIndex)
	}
	for _, iface := range interfaces {
		if iface.Sandbox == "" && iface.Name == link.Attrs().Name {
			return iface, nil
		}
	}

	return nil, fmt.Errorf("no veth peer of container interface found in host ns")
}

func validateSubnets(unshapedSubnets []string, shapedSubnets []string) error {
	if len(unshapedSubnets) > 0 && len(shapedSubnets) > 0 {
		return fmt.Errorf("unshapedSubnets and shapedSubnets cannot be both specified, one of them should be discarded")
	}

	for _, subnet := range unshapedSubnets {
		_, _, err := net.ParseCIDR(subnet)
		if err != nil {
			return fmt.Errorf("bad subnet %q provided, details %s", subnet, err)
		}
	}

	for _, subnet := range shapedSubnets {
		_, _, err := net.ParseCIDR(subnet)
		if err != nil {
			return fmt.Errorf("bad subnet %q provided, details %s", subnet, err)
		}
	}

	return nil
}

func cmdAdd(args *skel.CmdArgs) error {
	conf, err := parseConfig(args.StdinData)
	if err != nil {
		return err
	}

	bandwidth := getBandwidth(conf)
	if bandwidth == nil || bandwidth.isZero() {
		return types.PrintResult(conf.PrevResult, conf.CNIVersion)
	}

	if err = validateSubnets(bandwidth.UnshapedSubnets, bandwidth.ShapedSubnets); err != nil {
		return err
	}

	if conf.PrevResult == nil {
		return fmt.Errorf("must be called as chained plugin")
	}

	result, err := current.NewResultFromResult(conf.PrevResult)
	if err != nil {
		return fmt.Errorf("could not convert result to current version: %v", err)
	}

	netns, err := ns.GetNS(args.Netns)
	if err != nil {
		return fmt.Errorf("failed to open netns %q: %v", netns, err)
	}
	defer netns.Close()

	hostInterface, err := getHostInterface(result.Interfaces, args.IfName, netns)
	if err != nil {
		return err
	}

	if bandwidth.IngressRate > 0 && bandwidth.IngressBurst > 0 {
		err = CreateIngressQdisc(bandwidth.IngressRate, bandwidth.IngressBurst,
			bandwidth.UnshapedSubnets, bandwidth.ShapedSubnets, hostInterface.Name)
		if err != nil {
			return err
		}
	}

	if bandwidth.EgressRate > 0 && bandwidth.EgressBurst > 0 {
		mtu, qlen, err := getMTUAndQLen(hostInterface.Name)
		if err != nil {
			return err
		}

		ifbDeviceName := getIfbDeviceName(conf.Name, args.ContainerID)

		err = CreateIfb(ifbDeviceName, mtu, qlen)
		if err != nil {
			return err
		}

		ifbDevice, err := netlink.LinkByName(ifbDeviceName)
		if err != nil {
			return err
		}

		result.Interfaces = append(result.Interfaces, &current.Interface{
			Name: ifbDeviceName,
			Mac:  ifbDevice.Attrs().HardwareAddr.String(),
		})
		err = CreateEgressQdisc(bandwidth.EgressRate, bandwidth.EgressBurst,
			bandwidth.UnshapedSubnets, bandwidth.ShapedSubnets, hostInterface.Name,
			ifbDeviceName)
		if err != nil {
			return err
		}
	}

	return types.PrintResult(result, conf.CNIVersion)
}

func cmdDel(args *skel.CmdArgs) error {
	conf, err := parseConfig(args.StdinData)
	if err != nil {
		return err
	}

	ifbDeviceName := getIfbDeviceName(conf.Name, args.ContainerID)

	return TeardownIfb(ifbDeviceName)
}

func main() {
	skel.PluginMain(cmdAdd, cmdCheck, cmdDel, version.VersionsStartingFrom("0.3.0"), bv.BuildString("bandwidth"))
}

func SafeQdiscList(link netlink.Link) ([]netlink.Qdisc, error) {
	qdiscs, err := netlink.QdiscList(link)
	if err != nil {
		return nil, err
	}
	result := []netlink.Qdisc{}
	for _, qdisc := range qdiscs {
		// filter out pfifo_fast qdiscs because
		// older kernels don't return them
		_, pfifo := qdisc.(*netlink.PfifoFast)
		if !pfifo {
			result = append(result, qdisc)
		}
	}
	return result, nil
}

func cmdCheck(args *skel.CmdArgs) error {
	bwConf, err := parseConfig(args.StdinData)
	if err != nil {
		return err
	}

	if bwConf.PrevResult == nil {
		return fmt.Errorf("must be called as a chained plugin")
	}

	result, err := current.NewResultFromResult(bwConf.PrevResult)
	if err != nil {
		return fmt.Errorf("could not convert result to current version: %v", err)
	}

	netns, err := ns.GetNS(args.Netns)
	if err != nil {
		return fmt.Errorf("failed to open netns %q: %v", netns, err)
	}
	defer netns.Close()

	hostInterface, err := getHostInterface(result.Interfaces, args.IfName, netns)
	if err != nil {
		return err
	}
	link, err := netlink.LinkByName(hostInterface.Name)
	if err != nil {
		return err
	}

	bandwidth := getBandwidth(bwConf)

	if err = validateSubnets(bandwidth.UnshapedSubnets, bandwidth.ShapedSubnets); err != nil {
		return fmt.Errorf("failed to check subnets, details %s", err)
	}

	if bandwidth.IngressRate > 0 && bandwidth.IngressBurst > 0 {
		rateInBytes := bandwidth.IngressRate / 8
		burstInBytes := bandwidth.IngressBurst / 8
		bufferInBytes := buffer(rateInBytes, uint32(burstInBytes))
		err = checkHTB(link, rateInBytes, bufferInBytes, bandwidth.ShapedSubnets)
		if err != nil {
			return err
		}
	}
	if bandwidth.EgressRate > 0 && bandwidth.EgressBurst > 0 {
		rateInBytes := bandwidth.EgressRate / 8
		burstInBytes := bandwidth.EgressBurst / 8
		bufferInBytes := buffer(rateInBytes, uint32(burstInBytes))
		ifbDeviceName := getIfbDeviceName(bwConf.Name, args.ContainerID)
		ifbDevice, err := netlink.LinkByName(ifbDeviceName)
		if err != nil {
			return fmt.Errorf("get ifb device: %s", err)
		}
		err = checkHTB(ifbDevice, rateInBytes, bufferInBytes, bandwidth.ShapedSubnets)
		if err != nil {
			return err
		}
	}
	return nil
}

func checkHTB(link netlink.Link, rateInBytes uint64, bufferInBytes uint32, shapedSubnets []string) error {
	qdiscs, err := SafeQdiscList(link)
	if err != nil {
		return err
	}
	if len(qdiscs) == 0 {
		return fmt.Errorf("Failed to find qdisc")
	}
	foundHTB := false
	for _, qdisc := range qdiscs {
		htb, isHtb := qdisc.(*netlink.Htb)
		if !isHtb {
			continue
		}

		if foundHTB {
			return fmt.Errorf("Several htb qdisc found for device %s", link.Attrs().Name)
		}

		foundHTB = true
		defaultClassMinorID := ShapedClassMinorID
		if len(shapedSubnets) > 0 {
			defaultClassMinorID = UnShapedClassMinorID
		}

		if htb.Defcls != uint32(defaultClassMinorID) {
			return fmt.Errorf("Default class does not match")
		}

		classes, err := netlink.ClassList(link, htb.Handle)
		if err != nil {
			return fmt.Errorf("Unable to list classes bound to htb qdisc for device %s. Details %s",
				link.Attrs().Name, err)
		}
		if len(classes) != 2 {
			return fmt.Errorf("Number of htb classes does not match for device %s (%d != 2)",
				link.Attrs().Name, len(classes))
		}

		for _, c := range classes {
			htbClass, isHtb := c.(*netlink.HtbClass)
			if !isHtb {
				return fmt.Errorf("Unexpected class for parent htb qdisc bound to device %s", link.Attrs().Name)
			}
			if htbClass.Handle == htb.Defcls {
				if htbClass.Rate != rateInBytes {
					return fmt.Errorf("Rate does not match for the default class for device %s (%d != %d)",
						link.Attrs().Name, htbClass.Rate, rateInBytes)
				}

				if htbClass.Buffer != bufferInBytes {
					return fmt.Errorf("Burst buffer size does not match for the default class for device %s (%d != %d)",
						link.Attrs().Name, htbClass.Buffer, bufferInBytes)
				}
			} else if htbClass.Handle == netlink.MakeHandle(1, 1) {
				if htbClass.Rate != UncappedRate {
					return fmt.Errorf("Rate does not match for the uncapped class for device %s (%d != %d)",
						link.Attrs().Name, htbClass.Rate, UncappedRate)
				}
			}
		}

		// TODO: check subnet filters
	}

	return nil
}
