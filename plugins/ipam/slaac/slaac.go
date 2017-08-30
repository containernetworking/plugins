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
	"fmt"
	"io/ioutil"
	"path/filepath"
	"syscall"
	"time"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/cni/pkg/types/current"
	"github.com/containernetworking/cni/pkg/version"
	"github.com/containernetworking/plugins/pkg/ns"

	"github.com/vishvananda/netlink"
)

func setIPV6Sysctl(ifName, sysctl, value string) error {
	fileName := fmt.Sprintf("/proc/sys/net/ipv6/conf/%s/%s", ifName, sysctl)
	if err := ioutil.WriteFile(fileName, []byte(value), 0644); err != nil {
		return fmt.Errorf("failed to toggle %s/%s off: %v", ifName, filepath.Base(fileName), err)
	}
	return nil
}

func cmdAdd(args *skel.CmdArgs) error {
	// Plugin must return result in same version as specified in netconf
	versionDecoder := &version.ConfigDecoder{}
	confVersion, err := versionDecoder.Decode(args.StdinData)
	if err != nil {
		return err
	}

	netns, err := ns.GetNS(args.Netns)
	if err != nil {
		return fmt.Errorf("failed to open netns %q: %v", args.Netns, err)
	}
	defer netns.Close()

	result := &current.Result{}
	if err := netns.Do(func(_ ns.NetNS) error {
		link, err := netlink.LinkByName(args.IfName)
		if err != nil {
			return fmt.Errorf("failed to get container interface: %s", err)
		}

		for _, sysctl := range []string{"accept_ra", "accept_ra_defrtr", "accept_ra_pinfo", "accept_ra_mtu"} {
			if err := setIPV6Sysctl(args.IfName, sysctl, "1"); err != nil {
				return err
			}
		}

		if err := netlink.LinkSetDown(link); err != nil {
			return fmt.Errorf("failed to down container interface: %s", err)
		}
		// Toggle disable_ipv6 to force the kernel to listen for RAs again
		if err := setIPV6Sysctl(args.IfName, "disable_ipv6", "1"); err != nil {
			return err
		}
		time.Sleep(time.Second / 10)
		if err := setIPV6Sysctl(args.IfName, "disable_ipv6", "0"); err != nil {
			return err
		}
		if err := netlink.LinkSetUp(link); err != nil {
			return fmt.Errorf("failed to up container interface: %s", err)
		}

		// Ideally we'd use SubscribeAt() and just wait for the right
		// address to show up, but that has a data race that triggers
		// Go's race detection.
		// https://github.com/vishvananda/netlink/issues/240
		//
		// Wait up to 10s for a non-link-local address to show up
	loop:
		for i := 0; i < 100; i++ {
			addrs, err := netlink.AddrList(link, syscall.AF_UNSPEC)
			if err != nil {
				return fmt.Errorf("failed to list link %q addresses: %v", args.IfName, err)
			}
			for _, addr := range addrs {
				if addr.IP.To4() == nil &&
					(addr.Flags&syscall.IFA_F_TENTATIVE) == 0 &&
					(addr.Flags&syscall.IFA_F_DADFAILED) == 0 &&
					!addr.IP.IsLinkLocalUnicast() &&
					!addr.IP.IsLinkLocalMulticast() {
					result.IPs = []*current.IPConfig{
						{
							Version: "6",
							Address: *addr.IPNet,
						},
					}
					break loop
				}
			}
			time.Sleep(time.Second / 10)
		}
		if result.IPs == nil || len(result.IPs) != 1 {
			return fmt.Errorf("failed to acquire IPv6 address")
		}

		// Look for an IPv6 default route through the container interface,
		// from which we grab the gateway
		routes, err := netlink.RouteList(link, netlink.FAMILY_V6)
		if err != nil {
			return fmt.Errorf("failed to list %q IPv6 routes: %v", link.Attrs().Name, err)
		}
		for _, r := range routes {
			if r.Dst != nil {
				ones, _ := r.Dst.Mask.Size()
				if ones != 0 {
					// Non-default route; ignore
					continue
				}
			}
			result.IPs[0].Gateway = r.Gw
			break
		}

		// Disable accept_ra since we cannot yet deliver changes that
		// might come in a subsequent RA update back to the runtime
		// asynchronously.  The calling plugin will re-set the RA-provided
		// IP/routes/gateway making them static.
		if err := setIPV6Sysctl(args.IfName, "disable_ipv6", "0"); err != nil {
			return err
		}

		return nil
	}); err != nil {
		return err
	}

	return types.PrintResult(result, confVersion)
}

func cmdDel(args *skel.CmdArgs) error {
	// Nothing to do
	return nil
}

func main() {
	skel.PluginMain(cmdAdd, cmdDel, version.All)
}
