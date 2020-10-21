# vrf plugin

## Overview

This plugin creates a [VRF](https://www.kernel.org/doc/Documentation/networking/vrf.txt) in the network namespace and assigns it the interface passed in the arguments. If the VRF is already present in the namespace, it only adds the interface to it.

As a table id is mandatory, the plugin generates a new one for each different VRF that is added to the namespace.

It does not create any network interfaces and therefore does not bring connectivity by itself.
It is only useful when used in addition to other plugins.

## Operation

The following network configuration file

```json
{
    "cniVersion": "0.3.1",
    "name": "macvlan-vrf",
    "plugins": [
      {
        "type": "macvlan",
        "master": "eth0",
        "ipam": {
            "type": "dhcp"
        }
      },
      {
        "type": "vrf",
        "vrfname": "blue",
      }
    ]
}
```

will create a VRF named blue inside the target namespace (if not existing), and set it as master of the interface created by the previous plugin.

## Configuration

The only configuration is the name of the VRF, as per the following example:

```json
{
    "type": "vrf",
    "vrfname": "blue"
}
```

## Supported arguments

The following [args conventions](https://github.com/containernetworking/cni/blob/master/CONVENTIONS.md#args-in-network-config) are supported:

* `vrfname` (string, optional): The name of the VRF to be created and to be set as master of the interface
