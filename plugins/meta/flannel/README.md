# flannel plugin

## Overview
This plugin is designed to work in conjunction with [flannel](https://github.com/coreos/flannel), a network fabric for containers.
When flannel daemon is started, it outputs a `/run/flannel/subnet.env` file that looks like this:
```
FLANNEL_NETWORK=10.1.0.0/16
FLANNEL_SUBNET=10.1.17.1/24
FLANNEL_MTU=1472
FLANNEL_IPMASQ=true
```

This information reflects the attributes of flannel network on the host.
The flannel CNI plugin uses this information to configure another CNI plugin, such as bridge plugin.

## Operation
Given the following network configuration file and the contents of `/run/flannel/subnet.env` above,
```
{
	"name": "mynet",
	"type": "flannel"
}
```
the flannel plugin will generate another network configuration file:
```
{
	"name": "mynet",
	"type": "bridge",
	"mtu": 1472,
	"ipMasq": false,
	"isGateway": true,
	"ipam": {
		"type": "host-local",
		"subnet": "10.1.17.0/24"
	}
}
```

It will then invoke the bridge plugin, passing it the generated configuration.

As can be seen from above, the flannel plugin, by default, will delegate to the bridge plugin.
If additional configuration values need to be passed to the bridge plugin, it can be done so via the `delegate` field:
```
{
	"name": "mynet",
	"type": "flannel",
	"delegate": {
		"bridge": "mynet0",
		"mtu": 1400
	}
}
```

This supplies a configuration parameter to the bridge plugin -- the created bridge will now be named `mynet0`.
Notice that `mtu` has also been specified and this value will not be overwritten by flannel plugin.

Additionally, the `delegate` field can be used to select a different kind of plugin altogether.
To use `ipvlan` instead of `bridge`, the following configuration can be specified:

```
{
	"name": "mynet",
	"type": "flannel",
	"delegate": {
		"type": "ipvlan",
		"master": "eth0"
	}
}
```

## Network configuration reference

* `name` (string, required): the name of the network
* `type` (string, required): "flannel"
* `subnetFile` (string, optional): full path to the subnet file written out by flanneld. Defaults to /run/flannel/subnet.env
* `dataDir` (string, optional): path to directory where plugin will store generated network configuration files. Defaults to `/var/lib/cni/flannel`
* `delegate` (dictionary, optional): specifies configuration options for the delegated plugin.

flannel plugin will always set the following fields in the delegated plugin configuration:

* `name`: value of its "name" field.
* `ipam`: "host-local" type will be used with "subnet" set to `$FLANNEL_SUBNET`.

flannel plugin will set the following fields in the delegated plugin configuration if they are not present:
* `ipMasq`: the inverse of `$FLANNEL_IPMASQ`
* `mtu`: `$FLANNEL_MTU`

Additionally, for the bridge plugin, `isGateway` will be set to `true`, if not present.

## Windows Support (Experimental)
This plugin supports delegating to the windows CNI plugin (wincni.exe) to work in conjunction with [Flannel on Windows](https://github.com/coreos/flannel/issues/833). 
Flannel sets up an [HNS Network](https://docs.microsoft.com/en-us/virtualization/windowscontainers/manage-containers/container-networking) in L2Bridge mode for host-gw and 
in Overlay mode for vxlan. 

The following fields must be set in the delegated plugin configuration:
* `name` (string, required): the name of the network (must match the name in Flannel config / name of the HNS network)
* `type` (string, optional): for custom scenarios can be set to delegate to a plugin other than WINCNI
* `backendType` (string, optional): set to the Flannel backend mode being used, "host-gw" (default) or "vxlan" 
* `endpointMacPrefix` (string, optional): required for vxlan mode, set to the MAC prefix configured for Flannel  

For host-gw, the Flannel CNI plugin will set:
* `ipam` (string, required): subnet to `$FLANNEL_SUBNET` and GW to the .2 address in the `$FLANNEL_SUBNET` (this is required by HNS). IPAM type is left empty to allow Windows HNS to do IPAM

For vxlan, the Flannel CNI plugin will set:
* `ipam`: "host-local" type will be used with "subnet" set to `$FLANNEL_NETWORK` but limited to a range per `$FLANNEL_SUBNET` and gateway as the .1 address in `$FLANNEL_NETWORK`

If IPMASQ is true, the Flannel CNI plugin will setup an OutBoundNAT policy and add FLANNEL_SUBNET to any existing exclusions.

All other delegate config e.g. other HNS endpoint policis in AdditionalArgs will be passed to WINCNI as-is.    

Example VXLAN Flannel CNI config
```
{
	"name": "vxlan0",
	"type": "flannel",
	"delegate": {
		"backendType": "vxlan",
		"endpointMacPrefix": "0E-2A"
	}
}
```

For this example, Flannel CNI would generate the following config to delegate to WINCNI when FLANNEL_NETWORK=10.244.0.0/16, FLANNEL_SUBNET=10.244.1.0/24 and IPMASQ=true
```
{
	"name": "vxlan0",
	"type": "wincni.exe",
	"endpointMacPrefix": "0E-2A",
	"ipam": {
		"gateway": "10.244.0.1",
		"rangeEnd": "10.244.1.254",
		"rangeStart": "10.244.1.2",
		"subnet": "10.244.0.0/16",
		"type": "host-local"
	},
	"AdditionalArgs": [{
		"Name": "EndpointPolicy",
		"Value": {
			"ExceptionList": ["10.244.0.0/16"],
			"Type": "OutBoundNAT"
		}
	}]
}
```
