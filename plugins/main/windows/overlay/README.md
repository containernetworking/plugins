# L2Bridge  plugin (Windows)

## Overview

With Overlay plugin, all containers (on the same host) are plugged into an Overlay network based on VXLAN encapsulation. 


## Example configuration
```
{
	"name": "mynet",
	"type": "win-overlay",
	"ipMasq": true,
	"endpointMacPrefix": "0E-2A",
	"ipam": {
		"type": "host-local",
		"subnet": "10.10.0.0/16"
	}
}
```

## Network configuration reference

* `name` (string, required): the name of the network.
* `type` (string, required): "win-overlay".
* `endpointMacPrefix` (string, optional): required for vxlan mode, set to the MAC prefix configured for Flannel  
* `ipam` (dictionary, required): IPAM configuration to be used for this network.
