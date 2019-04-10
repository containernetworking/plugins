/*
Copied from netlink/link_linux.go
*/

package main

import (
	"fmt"
	"syscall"
	"unsafe"

	"github.com/vishvananda/netlink"
)

// VethPeerIndex get veth peer index.
func VethPeerIndex(link *netlink.Veth) (int, error) {
	fd, err := getSocketUDP()
	if err != nil {
		return -1, err
	}
	defer syscall.Close(fd)

	ifreq, sSet := newIocltStringSetReq(link.Name)
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), SIOCETHTOOL, uintptr(unsafe.Pointer(ifreq)))
	if errno != 0 {
		return -1, fmt.Errorf("SIOCETHTOOL request for %q failed, errno=%v", link.Attrs().Name, errno)
	}

	gstrings := &ethtoolGstrings{
		cmd:       ETHTOOL_GSTRINGS,
		stringSet: ETH_SS_STATS,
		length:    sSet.data[0],
	}
	ifreq.Data = uintptr(unsafe.Pointer(gstrings))
	_, _, errno = syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), SIOCETHTOOL, uintptr(unsafe.Pointer(ifreq)))
	if errno != 0 {
		return -1, fmt.Errorf("SIOCETHTOOL request for %q failed, errno=%v", link.Attrs().Name, errno)
	}

	stats := &ethtoolStats{
		cmd:    ETHTOOL_GSTATS,
		nStats: gstrings.length,
	}
	ifreq.Data = uintptr(unsafe.Pointer(stats))
	_, _, errno = syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), SIOCETHTOOL, uintptr(unsafe.Pointer(ifreq)))
	if errno != 0 {
		return -1, fmt.Errorf("SIOCETHTOOL request for %q failed, errno=%v", link.Attrs().Name, errno)
	}
	return int(stats.data[0]), nil
}
