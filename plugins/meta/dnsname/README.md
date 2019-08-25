# dnsname plugin

## Overview

This plugin creates firewall rules to allow traffic to/from container IP address via the host network .
It does not create any network interfaces and therefore does not set up connectivity by itself.
It is intended to be used as a chained plugins.

This plugin sets up the use of dnsmasq on a given CNI network so that Pods can resolve each other by name.  When configured,
the pod and its IP address are added to a network specific hosts file that dnsmasq will read in.  Similarly, when a pod
is removed from the network, it will remove the entry from the hosts file.  Each CNI network will have its own dnsmasq
instance.

## Usage
The dnsname plugin can be enabled in the cni network configuration file.

```
{
    "cniVersion": "0.4.0",
    "name": "cni-bridge-network",
    "plugins": [
      {
        "type": "bridge",
        "bridge": "cni0",
        ...
        }
      },
      {
        "type": "dnsname",
        "domainName": "foobar.com"
      }
    ]
}
```

## DNSMasq configuration files
The dnsmasq service and its configuration files are considered to be very fluid and are not meant to survive a system
reboot.  Therefore, files are stored in `/run/containers/cni/dnsname`. The plugin knows to recreate the necessary
files if it detects they are not present.

##  DNSMasq default configuration
Much like the implementation of DNSMasq for libvirt, this plugin will only set up dnsmasq to listen on the network
interfaces associated with the CNI network.  The DNSMasq services are not configured or managed by systemd but rather
only by the plugin itself.
