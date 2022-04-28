package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/containernetworking/plugins/plugins/ipam/dhcp"
	"github.com/containernetworking/plugins/plugins/ipam/host-local"
	"github.com/containernetworking/plugins/plugins/ipam/static"
	"github.com/containernetworking/plugins/plugins/main/bridge"
	"github.com/containernetworking/plugins/plugins/main/host-device"
	"github.com/containernetworking/plugins/plugins/main/ipvlan"
	"github.com/containernetworking/plugins/plugins/main/loopback"
	"github.com/containernetworking/plugins/plugins/main/macvlan"
	"github.com/containernetworking/plugins/plugins/main/ptp"
	"github.com/containernetworking/plugins/plugins/main/vlan"
	"github.com/containernetworking/plugins/plugins/meta/bandwidth"
	"github.com/containernetworking/plugins/plugins/meta/firewall"
	"github.com/containernetworking/plugins/plugins/meta/portmap"
	"github.com/containernetworking/plugins/plugins/meta/sbr"
	"github.com/containernetworking/plugins/plugins/meta/tuning"
	"github.com/containernetworking/plugins/plugins/meta/vrf"
)

type Plugin func()

var plugins map[string]Plugin = map[string]Plugin{
	"bandwidth":   bandwidth.Bandwidth,
	"bridge":      bridge.Bridge,
	"dhcp":        dhcp.Dhcp,
	"firewall":    firewall.Firewall,
	"host-device": hostdevice.HostDevice,
	"host-local":  hostlocal.HostLocal,
	"ipvlan":      ipvlan.Ipvlan,
	"loopback":    loopback.Loopback,
	"macvlan":     macvlan.Macvlan,
	"portmap":     portmap.Portmap,
	"ptp":         ptp.Ptp,
	"sbr":         sbr.Sbr,
	"static":      static.Static,
	"tuning":      tuning.Tuning,
	"vlan":        vlan.Vlan,
	"vrf":         vrf.Vrf,
}

func main() {
	pluginName := filepath.Base(os.Args[0])

	if pluginName == "plugins" {
		if len(os.Args) <= 1 {
			fmt.Printf("Built-in plugins:\n")
			for pluginName := range plugins {
				fmt.Println(pluginName)
			}
			os.Exit(0)
		}
		os.Args = os.Args[1:]
		pluginName = os.Args[0]
	}

	plugin, ok := plugins[pluginName]
	if !ok {
		fmt.Printf("Could not find plugin %s\n", pluginName)
		os.Exit(1)
	}

	plugin()
}
