# L2Bridge  plugin (Windows)

## Overview

With L2bridge plugin, all containers (on the same host) are plugged into an L2Bridge network that has one endpoint in the host namespace.


## Example configuration
```
{
	"name": "mynet",
	"type": "win-l2bridge",
	"ipMasq": true,
	"clusterNetworkPrefix": "10.244.0.0/16",
	"ipam": {
		"type": "host-local",
		"subnet": "10.10.0.0/16"
	}
}
```

## Network configuration reference

* `name` (string, required): the name of the network.
* `type` (string, required): "win-l2bridge".
* `ipMasq` (string, optional): Set to true to setup NAT for the clusterNetworkPrefix.
* `clusterNetworkPrefix` (string, optional): Used to setup NAT if ipMasq is set to true.
* `ipam` (dictionary, required): IPAM configuration to be used for this network.
