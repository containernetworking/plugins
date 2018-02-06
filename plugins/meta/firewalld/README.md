# firewalld plugin

## Overview

When firewalld is used on the host which is using CNI, the new IP addresses
(which are created for containers) are not registered, which means that the
network traffic from and to the container is blocked.

This plugin adds the IP address created by IPAM plugins to the specified
firewalld zone. It expects to be run as a chained plugin.

## Usage

You should use this plugin as part of a network configuration list. It
has one configuration option:

* `zone` - firewalld zone to which an IP address should be added (default:
`trusted`)

A sample config looks like:

```json
{
    "cniVersion": "0.3.1",
    "name": "bridge-firewalld",
    "plugins": [
      {
        "type": "bridge",
        "bridge": "cni0",
        "isGateway": true,
        "ipMasq": true,
        "ipam": {
            "type": "host-local",
            "subnet": "10.88.0.0/16",
            "routes": [
                { "dst": "0.0.0.0/0" }
            ]
        }
      },
      {
        "type": "firewalld",
        "zone": "trusted"
      }
    ]
}
```
