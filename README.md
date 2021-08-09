[![test](https://github.com/containernetworking/plugins/actions/workflows/test.yaml/badge.svg)](https://github.com/containernetworking/plugins/actions/workflows/test.yaml?query=branch%3Amaster)

# Plugins
Some CNI network plugins, maintained by the containernetworking team. For more information, see the [CNI website](https://www.cni.dev).

Read [CONTRIBUTING](CONTRIBUTING.md) for build and test instructions.

## Plugins supplied:
### Main: interface-creating
* `bridge`: Creates a bridge, adds the host and the container to it.
* `ipvlan`: Adds an [ipvlan](https://www.kernel.org/doc/Documentation/networking/ipvlan.txt) interface in the container.
* `loopback`: Set the state of loopback interface to up.
* `macvlan`: Creates a new MAC address, forwards all traffic to that to the container.
* `ptp`: Creates a veth pair.
* `vlan`: Allocates a vlan device.
* `host-device`: Move an already-existing device into a container.
#### Windows: Windows specific
* `win-bridge`: Creates a bridge, adds the host and the container to it.
* `win-overlay`: Creates an overlay interface to the container.
### IPAM: IP address allocation
* `dhcp`: Runs a daemon on the host to make DHCP requests on behalf of the container
* `host-local`: Maintains a local database of allocated IPs
* `static`:  Allocate a static IPv4/IPv6 addresses to container and it's useful in debugging purpose.

### Meta: other plugins
* `tuning`: Tweaks sysctl parameters of an existing interface
* `portmap`: An iptables-based portmapping plugin. Maps ports from the host's address space to the container.
* `bandwidth`: Allows bandwidth-limiting through use of traffic control tbf (ingress/egress).
* `sbr`: A plugin that configures source based routing for an interface (from which it is chained).
* `firewall`: A firewall plugin which uses iptables or firewalld to add rules to allow traffic to/from the container.

### Sample
The sample plugin provides an example for building your own plugin.

## Contact

For any questions about CNI, please reach out via:
- Email: [cni-dev](https://groups.google.com/forum/#!forum/cni-dev)
- Slack: #cni on the [CNCF slack](https://slack.cncf.io/).

If you have a _security_ issue to report, please do so privately to the email addresses listed in the [OWNERS](OWNERS.md) file.
