# firewall plugin

## Overview

This plugin creates firewall rules to allow traffic to/from container IP address via the host network .
It does not create any network interfaces and therefore does not set up connectivity by itself.
It is only useful when used in addition to other plugins.

## Operation
The following network configuration file

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
        "type": "firewall",
      }
    ]
}
```

will allow any IP addresses configured by earlier plugins to send/receive traffic via the host.

A successful result would simply be an empty result, unless a previous plugin passed a previous result, in which case this plugin will return that previous result.

## Backends

This plugin supports multiple firewall backends that implement the desired functionality.
Available backends include `iptables` and `firewalld` and may be selected with the `backend` key.
If no `backend` key is given, the plugin will use firewalld if the service exists on the D-Bus system bus.
If no firewalld service is found, it will fall back to iptables.

When the `iptables` backend is used, the above example will create two new iptables chains in the `filter` table and add rules that allow the given interface to send/receive traffic.
When the `firewalld` backend is used, the above example will place the `cni0` interface into firewalld's `trusted` zone, allowing it to send/receive traffic.


