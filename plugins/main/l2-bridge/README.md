# l2-bridge plugin

## Overview

With l2-bridge plugin, all containers (on the same host) are plugged into a bridge (virtual switch) that resides in the host network namespace.
The containers receive one end of the veth pair with the other end connected to the bridge.
No IP address is assigned to the veth pair.

The network configuration specifies the name of the bridge to be used.
If the bridge is missing, the plugin will create one on first use.


## Example configuration
```
{
    "name": "mynet",
	"cniVersion": "0.3.0",
	"type": "l2-bridge",
	"bridge": "mynet0",
	"ipam": {}
}
```

## Network configuration reference

* `name` (string, required): the name of the network.
* `type` (string, required): "l2-bridge".
* `bridge` (string, optional): name of the bridge to use.
* `mtu` (integer, optional): explicitly set MTU to the specified value. Defaults to the value chosen by the kernel.
* `hairpinMode` (boolean, optional): set hairpin mode for interfaces on the bridge. Defaults to false.
* `ipam` (dictionary, required): Need to be an empty dictionary.
* `promiscMode` (boolean, optional): set promiscuous mode on the bridge. Defaults to false.
