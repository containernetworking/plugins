# firewall plugin

## Overview

This plugin creates firewall rules to allow traffic to/from container IP address via the host network .
It does not create any network interfaces and therefore does not set up connectivity by itself.
It is intended to be used as a chained plugins.

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
        "type": "firewall"
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

## firewalld backend rule structure
When the `firewalld` backend is used, this example will place the IPAM allocated address for the container (e.g. 10.88.0.2) into firewalld's `trusted` zone, allowing it to send/receive traffic.


A sample standalone config list (with the file extension .conflist) using firewalld backend might
look like:

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
        "backend": "firewalld"
      }
    ]
}
```


`FORWARD_IN_ZONES_SOURCE` chain:
- `-d 10.88.0.2 -j FWDI_trusted`

`CNI_FORWARD_OUT_ZONES_SOURCE` chain:
- `-s 10.88.0.2 -j FWDO_trusted`


## iptables backend rule structure

A sample standalone config list (with the file extension .conflist) using iptables backend might
look like:

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
        "backend": "iptables"
      }
    ]
}
```

When the `iptables` backend is used, the above example will create two new iptables chains in the `filter` table and add rules that allow the given interface to send/receive traffic.

### FORWARD
A new chain, CNI-FORWARD is added to the FORWARD chain.  CNI-FORWARD is the chain where rules will be added
when containers are created and from where rules will be removed when containers terminate.

`FORWARD` chain:
- `-j CNI-FORWARD`

CNI-FORWARD will have a pair of rules added, one for each direction, using the IPAM assigned IP address
of the container as shown:

`CNI-FORWARD` chain:
- `-s 10.88.0.2 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT`
- `-d 10.88.0.2 -j ACCEPT`

## nftables backend rule structure

The prerequisite for the backend is the existence of `filter` table and
the existence of `FORWARD` chain in the table.

A sample standalone config list (with the file extension `.conflist`) using
`nftables` backend might look like:

```json
{
   "cniVersion": "0.4.0",
   "name": "podman",
   "plugins": [
      {
         "type": "bridge",
         "bridge": "cni-podman0",
         "isGateway": true,
         "ipMasq": true,
         "ipam": {
            "type": "host-local",
            "routes": [
               {
                  "dst": "0.0.0.0/0"
               }
            ],
            "ranges": [
               [
                  {
                     "subnet": "192.168.100.0/24",
                     "gateway": "192.168.100.1"
                  }
               ]
            ]
         }
      },
      {
         "type": "portmap",
         "capabilities": {
            "portMappings": true
         }
      },
      {
         "type": "firewall",
         "backend": "nftables"
      }
   ]
}
```

Prior to the invocation of CNI `firewall` plugin, the `FORWARD` chain in `filter`
table might be configured be as follows:

```
table ip filter {
        chain FORWARD { # handle 1
                type filter hook forward priority filter; policy drop;
                log prefix "IPv4 FORWARD drop: " flags all # handle 28
                counter packets 0 bytes 0 drop # handle 29
        }
}
```

Subsequently, the plugin creates "non-base chain", e.g. `cnins-3-4026543850-dummy0`
and link it to `FORWARD` chain
via [`jump` instruction](https://wiki.nftables.org/wiki-nftables/index.php/Jumping_to_chain).

```
table ip filter {
        chain FORWARD { # handle 1
                type filter hook forward priority filter; policy drop;
                jump cnins-3-4026543850-dummy0 # handle 10
                log prefix "IPv4 FORWARD drop: " flags all # handle 28
                counter packets 0 bytes 0 drop # handle 29
        }

        chain cnins-3-4026543850-dummy0 { # handle 2
                oifname "dummy0" ip daddr 192.168.100.100 ct state established,related counter packets 0 bytes 0 accept # handle 3
                iifname "dummy0" ip saddr 192.168.100.100 counter packets 0 bytes 0 accept # handle 4
                iifname "dummy0" oifname "dummy0" counter packets 0 bytes 0 accept # handle 5
        }
}
```

The name of the chain is is prefixed with `CNINS-` and followed by `Dev` and `Ino`
of `Stat_t` struct. See [here](https://github.com/vishvananda/netns/blob/master/netns.go#L60)
for more information.

Generally, the testing of nftables backend of this plugin begins with defining
the data structure the plugin would receive when processing a request.
In this example, the plugin received single interface `dummy0`, with IPv4 and
IPv6 addresses.

```json
{
  "name": "test",
  "type": "firewall",
  "backend": "nftables",
  "ifName": "dummy0",
  "cniVersion": "0.4.0",
  "prevResult": {
    "interfaces": [
      {
        "name": "dummy0"
      }
    ],
    "ips": [
      {
        "version": "4",
        "address": "192.168.200.10/24",
        "interface": 0
      },
      {
        "version": "6",
        "address": "2001:db8:1:2::1/64",
        "interface": 0
      }
    ]
  }
}
```

Prior to running tests, the test harness does the following:

1. creates `originalNS` namespace
2. adds `dummy0` interface to `originalNS` via Netlink
3. checks that the `dummy0` interface is available in the `originalNS`
4. creates `targetNS` namespace

Upon the completion of the testing, the test harness does the following:

1. closes `originalNS` namespace
2. closes `targetNS` namespace

The tests in the harness start with `It()`.

Generally, a test contains a number of input arguments. In the case of
"installs nftables rules, checks the rules exist, then cleans up on delete using v4.0.x",
the test has the following arguments:

* container id: `dummy`
* the path to container namespace, i.e. `targetNS`
* the name of the interface
* the JSON payload containing a dummy request

The test uses the same arguments and runs the following operations in
`originalNS` namespace:

* `cmdAdd`
* `cmdCheck`
* `cmdDel`

The operations correspond to the following functions:

| **Operation** | **Function** |
| --- | --- |
| `cmdAdd` | `func (nb *nftBackend) Add(conf *FirewallNetConf, result *current.Result)` |
| `cmdCheck` | `func (nb *nftBackend) Del(conf *FirewallNetConf, result *current.Result)` |
| `cmdDel` | `func (nb *nftBackend) Check(conf *FirewallNetConf, result *current.Result)` |

The following command triggers the testing of `firewall` plugin:

```bash
sudo go test -v ./plugins/meta/firewall
```

At the outset, the test outputs dummy host and container namespaces:

```
Host Namespace: /var/run/netns/cnitest-ba94096d-68e1-90c0-5e0a-4acf3a8339cd
Container Namespace: /var/run/netns/cnitest-762bc306-9af5-5882-af95-e011590ce8d3
```

The knowing the last part of the namespace path helps inspecting namespaces
with `sudo ip netns exec` command. For example, the following command
show `nftables` tables, chains, and rules.

```bash

$ sudo ip netns exec cnitest-ba94096d-68e1-90c0-5e0a-4acf3a8339cd nft list ruleset
table ip filter {
        chain FORWARD {
                type filter hook forward priority filter; policy drop;
                jump cnins-3-4026550857-dummy0
        }

        chain cnins-3-4026550857-dummy0 {
                oifname "dummy0" ip daddr 192.168.100.100 ct state established,related counter packets 0 bytes 0 accept
                iifname "dummy0" ip saddr 192.168.100.100 counter packets 0 bytes 0 accept
                iifname "dummy0" oifname "dummy0" counter packets 0 bytes 0 accept
        }
}
table ip6 filter {
        chain FORWARD {
                type filter hook forward priority filter; policy drop;
                jump cnins-3-4026550857-dummy0
        }

        chain cnins-3-4026550857-dummy0 {
                oifname "dummy0" ip6 daddr 2001:db8:100:100::1 ct state established,related counter packets 0 bytes 0 accept
                iifname "dummy0" ip6 saddr 2001:db8:100:100::1 counter packets 0 bytes 0 accept
                iifname "dummy0" oifname "dummy0" counter packets 0 bytes 0 accept
        }
}
```
