
This document has moved to the [containernetworking/cni.dev](https://github.com/containernetworking/cni.dev) repo.

You can find it online here: https://cni.dev/plugins/current/ipam/dhcp/

# Dev
`sudo rm -f /run/cni/dhcp.sock`

`sudo go run . daemon`

# Building
`go build`

`sudo rm -f /run/cni/dhcp.sock`

`sudo ./dhcp daemon`

# New option
`sudo nano /etc/cni/multus/net.d/sw-lan.conf`

```json
{
    "cniVersion": "0.4.0",
    "type": "macvlan",
    "name": "sw-lan",
    "master": "eno1",
    "mode": "bridge",
    "ipam": {
        "type": "dhcp",
        "discardDhcpRoutes": true
    }
}
```

**discardDhcpRoutes** is set to false by default. If set to true, it will prevent the dhcp plugin to update the container/pod ip route table.
