---
title: dummy plugin
description: "plugins/main/dummy/README.md"
date: 2022-05-12
toc: true
draft: true
weight: 200
---

## Overview

dummy is a useful feature for routing packets through the Linux kernel without transmitting.

Like loopback, it is a purely virtual interface that allows packets to be routed to a designated IP address. Unlike loopback, the IP address can be arbitrary and is not restricted to the `127.0.0.0/8` range.

## Example configuration

```json
{
	"name": "mynet",
	"type": "dummy",
	"ipam": {
		"type": "host-local",
		"subnet": "10.1.2.0/24"
	}
}
```

## Network configuration reference

* `name` (string, required): the name of the network.
* `type` (string, required): "dummy".
* `ipam` (dictionary, required): IPAM configuration to be used for this network.

## Notes

* `dummy` does not transmit packets.
Therefore the container will not be able to reach any external network.
This solution is designed to be used in conjunction with other CNI plugins (e.g., `bridge`) to provide an internal non-loopback address for applications to use.
