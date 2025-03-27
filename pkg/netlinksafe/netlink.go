// Package netlinksafe wraps vishvandanda/netlink functions that may return EINTR.
//
// A Handle instantiated using [NewHandle] or [NewHandleAt] can be used in place
// of a netlink.Handle, it's a wrapper that replaces methods that need to be
// wrapped. Functions that use the package handle need to be called as "netlinksafe.X"
// instead of "netlink.X".
//
// The wrapped functions currently return EINTR when NLM_F_DUMP_INTR flagged
// in a netlink response, meaning something changed during the dump so results
// may be incomplete or inconsistent.
//
// At present, the possibly incomplete/inconsistent results are not returned
// by netlink functions along with the EINTR. So, it's not possible to do
// anything but retry. After maxAttempts the EINTR will be returned to the
// caller.
package netlinksafe

import (
	"log"

	"github.com/pkg/errors"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"github.com/vishvananda/netns"
)

// Arbitrary limit on max attempts at netlink calls if they are repeatedly interrupted.
const maxAttempts = 5

type Handle struct {
	*netlink.Handle
}

func NewHandle(nlFamilies ...int) (Handle, error) {
	nlh, err := netlink.NewHandle(nlFamilies...)
	if err != nil {
		return Handle{}, err
	}
	return Handle{nlh}, nil
}

func NewHandleAt(ns netns.NsHandle, nlFamilies ...int) (Handle, error) {
	nlh, err := netlink.NewHandleAt(ns, nlFamilies...)
	if err != nil {
		return Handle{}, err
	}
	return Handle{nlh}, nil
}

func (h Handle) Close() {
	if h.Handle != nil {
		h.Handle.Close()
	}
}

func retryOnIntr(f func() error) {
	for attempt := 0; attempt < maxAttempts; attempt++ {
		if err := f(); !errors.Is(err, netlink.ErrDumpInterrupted) {
			return
		}
	}
	log.Printf("netlink call interrupted after %d attempts", maxAttempts)
}

func discardErrDumpInterrupted(err error) error {
	if errors.Is(err, netlink.ErrDumpInterrupted) {
		// The netlink function has returned possibly-inconsistent data along with the
		// error. Discard the error and return the data. This restores the behaviour of
		// the netlink package prior to v1.2.1, in which NLM_F_DUMP_INTR was ignored in
		// the netlink response.
		log.Printf("discarding ErrDumpInterrupted: %+v", errors.WithStack(err))
		return nil
	}
	return err
}

// AddrList calls netlink.AddrList, retrying if necessary.
func AddrList(link netlink.Link, family int) ([]netlink.Addr, error) {
	var addrs []netlink.Addr
	var err error
	retryOnIntr(func() error {
		addrs, err = netlink.AddrList(link, family) //nolint:forbidigo
		return err
	})
	return addrs, discardErrDumpInterrupted(err)
}

// LinkByName calls h.Handle.LinkByName, retrying if necessary. The netlink function
// doesn't normally ask the kernel for a dump of links. But, on an old kernel, it
// will do as a fallback and that dump may get inconsistent results.
func (h Handle) LinkByName(name string) (netlink.Link, error) {
	var link netlink.Link
	var err error
	retryOnIntr(func() error {
		link, err = h.Handle.LinkByName(name) //nolint:forbidigo
		return err
	})
	return link, discardErrDumpInterrupted(err)
}

// LinkByName calls netlink.LinkByName, retrying if necessary. The netlink
// function doesn't normally ask the kernel for a dump of links. But, on an old
// kernel, it will do as a fallback and that dump may get inconsistent results.
func LinkByName(name string) (netlink.Link, error) {
	var link netlink.Link
	var err error
	retryOnIntr(func() error {
		link, err = netlink.LinkByName(name) //nolint:forbidigo
		return err
	})
	return link, discardErrDumpInterrupted(err)
}

// LinkList calls h.Handle.LinkList, retrying if necessary.
func (h Handle) LinkList() ([]netlink.Link, error) {
	var links []netlink.Link
	var err error
	retryOnIntr(func() error {
		links, err = h.Handle.LinkList() //nolint:forbidigo
		return err
	})
	return links, discardErrDumpInterrupted(err)
}

// LinkList calls netlink.Handle.LinkList, retrying if necessary.
func LinkList() ([]netlink.Link, error) {
	var links []netlink.Link
	var err error
	retryOnIntr(func() error {
		links, err = netlink.LinkList() //nolint:forbidigo
		return err
	})
	return links, discardErrDumpInterrupted(err)
}

// RouteList calls h.Handle.RouteList, retrying if necessary.
func (h Handle) RouteList(link netlink.Link, family int) ([]netlink.Route, error) {
	var routes []netlink.Route
	var err error
	retryOnIntr(func() error {
		routes, err = h.Handle.RouteList(link, family) //nolint:forbidigo
		return err
	})
	return routes, err
}

// RouteList calls netlink.RouteList, retrying if necessary.
func RouteList(link netlink.Link, family int) ([]netlink.Route, error) {
	var route []netlink.Route
	var err error
	retryOnIntr(func() error {
		route, err = netlink.RouteList(link, family) //nolint:forbidigo
		return err
	})
	return route, discardErrDumpInterrupted(err)
}

// BridgeVlanList calls netlink.BridgeVlanList, retrying if necessary.
func BridgeVlanList() (map[int32][]*nl.BridgeVlanInfo, error) {
	var err error
	var info map[int32][]*nl.BridgeVlanInfo
	retryOnIntr(func() error {
		info, err = netlink.BridgeVlanList() //nolint:forbidigo
		return err
	})
	return info, discardErrDumpInterrupted(err)
}

// RouteListFiltered calls h.Handle.RouteListFiltered, retrying if necessary.
func (h Handle) RouteListFiltered(family int, filter *netlink.Route, filterMask uint64) ([]netlink.Route, error) {
	var routes []netlink.Route
	var err error
	retryOnIntr(func() error {
		routes, err = h.Handle.RouteListFiltered(family, filter, filterMask) //nolint:forbidigo
		return err
	})
	return routes, err
}

// RouteListFiltered calls netlink.RouteListFiltered, retrying if necessary.
func RouteListFiltered(family int, filter *netlink.Route, filterMask uint64) ([]netlink.Route, error) {
	var route []netlink.Route
	var err error
	retryOnIntr(func() error {
		route, err = netlink.RouteListFiltered(family, filter, filterMask) //nolint:forbidigo
		return err
	})
	return route, discardErrDumpInterrupted(err)
}

// QdiscList calls netlink.QdiscList, retrying if necessary.
func QdiscList(link netlink.Link) ([]netlink.Qdisc, error) {
	var qdisc []netlink.Qdisc
	var err error
	retryOnIntr(func() error {
		qdisc, err = netlink.QdiscList(link) //nolint:forbidigo
		return err
	})
	return qdisc, discardErrDumpInterrupted(err)
}

// QdiscList calls h.Handle.QdiscList, retrying if necessary.
func (h *Handle) QdiscList(link netlink.Link) ([]netlink.Qdisc, error) {
	var qdisc []netlink.Qdisc
	var err error
	retryOnIntr(func() error {
		qdisc, err = h.Handle.QdiscList(link) //nolint:forbidigo
		return err
	})
	return qdisc, err
}

// LinkGetProtinfo calls netlink.LinkGetProtinfo, retrying if necessary.
func LinkGetProtinfo(link netlink.Link) (netlink.Protinfo, error) {
	var protinfo netlink.Protinfo
	var err error
	retryOnIntr(func() error {
		protinfo, err = netlink.LinkGetProtinfo(link) //nolint:forbidigo
		return err
	})
	return protinfo, discardErrDumpInterrupted(err)
}

// LinkGetProtinfo calls h.Handle.LinkGetProtinfo, retrying if necessary.
func (h *Handle) LinkGetProtinfo(link netlink.Link) (netlink.Protinfo, error) {
	var protinfo netlink.Protinfo
	var err error
	retryOnIntr(func() error {
		protinfo, err = h.Handle.LinkGetProtinfo(link) //nolint:forbidigo
		return err
	})
	return protinfo, err
}

// RuleListFiltered calls netlink.RuleListFiltered, retrying if necessary.
func RuleListFiltered(family int, filter *netlink.Rule, filterMask uint64) ([]netlink.Rule, error) {
	var rules []netlink.Rule
	var err error
	retryOnIntr(func() error {
		rules, err = netlink.RuleListFiltered(family, filter, filterMask) //nolint:forbidigo
		return err
	})
	return rules, discardErrDumpInterrupted(err)
}

// RuleListFiltered calls h.Handle.RuleListFiltered, retrying if necessary.
func (h *Handle) RuleListFiltered(family int, filter *netlink.Rule, filterMask uint64) ([]netlink.Rule, error) {
	var rules []netlink.Rule
	var err error
	retryOnIntr(func() error {
		rules, err = h.Handle.RuleListFiltered(family, filter, filterMask) //nolint:forbidigo
		return err
	})
	return rules, err
}

// FilterList calls netlink.FilterList, retrying if necessary.
func FilterList(link netlink.Link, parent uint32) ([]netlink.Filter, error) {
	var filters []netlink.Filter
	var err error
	retryOnIntr(func() error {
		filters, err = netlink.FilterList(link, parent) //nolint:forbidigo
		return err
	})
	return filters, discardErrDumpInterrupted(err)
}

// FilterList calls h.Handle.FilterList, retrying if necessary.
func (h *Handle) FilterList(link netlink.Link, parent uint32) ([]netlink.Filter, error) {
	var filters []netlink.Filter
	var err error
	retryOnIntr(func() error {
		filters, err = h.Handle.FilterList(link, parent) //nolint:forbidigo
		return err
	})
	return filters, err
}

// RuleList calls netlink.RuleList, retrying if necessary.
func RuleList(family int) ([]netlink.Rule, error) {
	var rules []netlink.Rule
	var err error
	retryOnIntr(func() error {
		rules, err = netlink.RuleList(family) //nolint:forbidigo
		return err
	})
	return rules, discardErrDumpInterrupted(err)
}

// RuleList calls h.Handle.RuleList, retrying if necessary.
func (h *Handle) RuleList(family int) ([]netlink.Rule, error) {
	var rules []netlink.Rule
	var err error
	retryOnIntr(func() error {
		rules, err = h.Handle.RuleList(family) //nolint:forbidigo
		return err
	})
	return rules, err
}

// ConntrackDeleteFilters calls netlink.ConntrackDeleteFilters, retrying if necessary.
func ConntrackDeleteFilters(table netlink.ConntrackTableType, family netlink.InetFamily, filters ...netlink.CustomConntrackFilter) (uint, error) {
	var deleted uint
	var err error
	retryOnIntr(func() error {
		deleted, err = netlink.ConntrackDeleteFilters(table, family, filters...) //nolint:forbidigo
		return err
	})
	return deleted, discardErrDumpInterrupted(err)
}

// ConntrackDeleteFilters calls h.Handle.ConntrackDeleteFilters, retrying if necessary.
func (h *Handle) ConntrackDeleteFilters(table netlink.ConntrackTableType, family netlink.InetFamily, filters ...netlink.CustomConntrackFilter) (uint, error) {
	var deleted uint
	var err error
	retryOnIntr(func() error {
		deleted, err = h.Handle.ConntrackDeleteFilters(table, family, filters...) //nolint:forbidigo
		return err
	})
	return deleted, err
}
