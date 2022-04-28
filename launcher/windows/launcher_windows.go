package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/containernetworking/plugins/plugins/ipam/host-local"
	"github.com/containernetworking/plugins/plugins/main/windows/win-bridge"
	"github.com/containernetworking/plugins/plugins/main/windows/win-overlay"
)

type Plugin func()

var plugins map[string]Plugin = map[string]Plugin{
	"host-local":  hostlocal.HostLocal,
	"win-bridge":  winbridge.WinBridge,
	"win-overlay": winoverlay.WinOverlay,
}

func main() {
	pluginName := strings.TrimSuffix(filepath.Base(os.Args[0]), ".exe")

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
