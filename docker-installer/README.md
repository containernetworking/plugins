This scripts are used in the docker image.

The docker image installs the plug-ins to /host/opt/cni/bin which should be bind-mounted to /opt/cni/bin on the host.

The installer-script keeps track of plug-ins it installs and ensures:
- that no existing plug-ins that have been installed or updated by someone else are overwriten
- that plug-ins installed by this script are updated if a new version of this image is used

A unit-test shell script for the installer script is part of the docker build process.
