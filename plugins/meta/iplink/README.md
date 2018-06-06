# iplink plugin

## Overview

This plugin changes some interface attributes, like 'ip link' command.
It does not create any network interfaces and therefore does not bring connectivity by itself.
This iplink plugin applies changes to interfaces created by previously applied plugins as meta plugin.
It is only useful when used in addition to other plugins.

## Example configuration

```json
{
  "cniVersion": "0.3.1",
  "name": "mynet",
  "plugins": [
    {
      "type": "ptp",
      "ipMasq": true,
      "mtu": 512,
      "ipam": {
          "type": "host-local",
          "subnet": "10.0.0.0/24"
      },
      "dns": {
        "nameservers": [ "10.1.0.1" ]
      }
    },
    {
      "name": "myiplink",
      "type": "iplink",
      "promisc": true,
      "mac": "c2:b0:57:49:47:f1",
      "mtu": 1454
    }
  ]
}
```

## Network configuration reference

* `type` (string, required): "iplink"
* `mac` (string, optional): MAC address (i.e. hardware address) of interface
* `mtu` (integer, optional): MTU of interface
* `promisc` (bool, optional): Change the promiscas mode of interface

## Supported arguments
The following [CNI_ARGS](https://github.com/containernetworking/cni/blob/master/SPEC.md#parameters) are supported:

* `MAC`: request a specific MAC address for the interface 

    (example: CNI_ARGS="IgnoreUnknown=true;MAC=c2:11:22:33:44:55")

Note: You may add `IgnoreUnknown=true` to allow loose CNI argument verification (see CNI's issue[#560](https://github.com/containernetworking/cni/issues/560)).
