# route-override: Meta CNI plugin for overriding IP route

## Overview
 route-override IPAM works as meta CNI plugin to override IP route given by previous CNI plugins.
It is useful in multiple interface case with [network-attachment-definition](https://github.com/K8sNetworkPlumbingWG/multi-net-spec) to change the destination to specific interface, not default route.

## Example Configuration

```
{
    "cniVersion": "0.3.0",
    "name" : "mymacvlan",
    "plugins": [
    {
        "type": "macvlan",
        "master": "eth1",
        "mode": "bridge",
        "ipam": {
            ...
        }
    },
    {
        "type" : "route-override",
        "del": [
        {
            "dst": "192.168.0.0/24"
        }],
        "add": [
        {
            "dst": "192.168.0.0/24",
            "gw": "10.1.254.254"
        }]
    }
    ]
}
```

## Configuration Reference

* `type`: (string, required): "routing-override"
* `flushExisting`: (bool, optional): set it `true` if you flush all routes.
* `flushDefaultGateway`: (bool, optional): set it `true` if you flush default route (gateway).
* `del`: (object, optional): list of routes to delete from the container namespace. Each route is a dictionary with "dst" and optional "gw" fields. If "gw" is omitted, "gateway" in the previous plugin results will be used.
* `add`: (object, optional): list of routes to add to the container namespace. Each route is a dictionary with "dst" and optional "gw" fields. If "gw" is omitted, "gateway" in the previous plugin results will be used.
* `skipcheck`: (bool, optional): set it to `true` if there will be any changes in routes between `add`/`del` calls of this plugin.

## Process Sequence

`route-override` will manipulate the routes as following sequences:

1. flush routes if `flushExisting` is enabled.
1. flush gateway if `flushDefaultGateway` is enabled.
1. if `del` is non empty - attempt to delete all listed in this variable routes. Missing routes are ignored.
1. add all routes listed in `add`

## Supported Arguments

The following ["args" conventions](https://github.com/containernetworking/cni/blob/master/CONVENTIONS.md#args-in-network-config) are supported:
All arguments is the same as configuration reference above.

* `flushExisting`: (bool, optional)
* `flushDefaultGateway`: (bool, optional)
* `del`: (object, optional)
* `add`: (object, optional)
