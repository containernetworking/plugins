# win-bridge plugin

## Overview

With win-bridge plugin, all containers (on the same host) are plugged into an L2Bridge network that has one endpoint in the host namespace.

## Example configuration
```
{
	"name": "mynet",
	"type": "win-bridge",
	"ipMasqNetwork": "10.244.0.0/16",
	"ipam": {
		"type": "host-local",
		"subnet": "10.10.0.0/16"
	}
}
```

## Network configuration reference

* `name` (string, required): the name of the network.
* `type` (string, required): "win-bridge".
* `ipMasqNetwork` (string, optional): setup NAT if not empty.
* `ipam` (dictionary, required): IPAM configuration to be used for this network.
