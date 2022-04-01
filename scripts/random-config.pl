#!/usr/bin/perl

# Generates a (somewhat) random CNI configuration
# What could possibly go wrong?

use strict;

# Copied and pasted from something that predates stackoverflow.
srand(time() ^ ($$ + ($$ << 15)));
# At least it's a documentation range ¯\_(ツ)_/¯
my $ipaddr = "192.0.2.".int(rand(255));

# One in a hundred shot this configuration is named "bob"
my $cni_name;
if (int(rand(100)) eq "99") {
  $cni_name = "bob";
} else {
  $cni_name = "randomcni".int(rand(255));
}

# IPAM CNI templates.

my $template_ipam_dhcp = qq!{
    "type": "dhcp"
  }!;

my $template_ipam_hostlocal = qq!{
    "type": "host-local",
    "subnet": "$ipaddr/24"
  }!;

my $template_ipam_static = qq!{
    "type": "static",
    "addresses": [
      {
        "address": "$ipaddr/24"
      }
    ]
  }!;

my @ipam_template = ($template_ipam_dhcp,$template_ipam_hostlocal,$template_ipam_static);

my $ipam = $ipam_template[ rand @ipam_template ];

# It's kind of Perl standard to keep around stuff you don't use as comments
# these are intended to confuse future maintainers.
# print $ipam."\n";

# Grab a random net device off the system
my $iplinkshow = `ip link show`;
my @lines = split(/\n/, $iplinkshow);
my @devs = ();
foreach my $d(@lines) {
  if ($d =~ m/^\d/) {
    $d =~ s/^\d+?: (.+?):.+$/$1/;
    push(@devs,$d);
  }
}

my $dev = $devs[ rand @devs ];

# Main CNI plugin templates.

my $template_vlan = qq!{
  "name": "$cni_name",
  "cniVersion": "0.3.1",
  "type": "vlan",
  "master": "$dev",
  "mtu": 1500,
  "vlanId": 5,
  "ipam": $ipam
}!;

my $brnumber = int(rand(100));
my $template_bridge = qq!{
  "cniVersion": "0.3.1",
  "name": "$cni_name",
  "type": "bridge",
  "bridge": "cni$brnumber",
  "isDefaultGateway": true,
  "forceAddress": false,
  "ipMasq": true,
  "hairpinMode": true,
  "ipam": $ipam
}!;

my $template_ipvlan = qq!{
  "name": "$cni_name",
  "type": "ipvlan",
  "master": "$dev",
  "ipam": $ipam
}!;

my $template_macvlan = qq!{
  "name": "$cni_name",
  "type": "macvlan",
  "master": "$dev",
  "ipam": {
    "type": "dhcp"
  }
}!;

my $template_ptp = qq!{
  "name": "$cni_name",
  "type": "ptp",
  "ipam": $ipam
}!;


my @config_template = ($template_vlan,$template_bridge,$template_ipvlan,$template_macvlan,$template_ptp);

my $cni_config = $config_template[ rand @config_template ];

print $cni_config."\n";
