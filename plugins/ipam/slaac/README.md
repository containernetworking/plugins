# slaac plugin

## Overview

This plugin utilizes the kernel's IPv6 SLAAC capabilities to deliver an IPv6
address composed of the interface's identifier and the prefix provided by an
IPv6 router.  Since CNI cannot yet deliver changes back to the runtime
asynchronously, and because any of the RA-provided details could change with
the next RA, the plugin turns off acceptance of RAs once it has acquired the
inteface IP address, routes, and gateway, and relies on the calling plugin
to re-add the IP address and routes, which will make them static.

## TODO
* Neighbor Discover user options (RDNSS, DNSSL)
* Honor M/O bit and run DHCPv6 as required
* Handle updates to RA-provided details when the RA changes, and once CNI gains
some mechanism for sending those to the calling plugin/runtime asynchronously

## Example configuration

```
{
	"ipam": {
		"type": "slaac",
	}
}

## Network configuration reference

* `type` (string, required): "slaac"
