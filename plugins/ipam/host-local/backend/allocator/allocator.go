// Copyright 2015 CNI authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package allocator

import (
	"encoding/base64"
	"fmt"
	"log"
	"net"
	"os"

	"github.com/containernetworking/cni/pkg/types/current"
	"github.com/containernetworking/plugins/pkg/ip"
	"github.com/containernetworking/plugins/plugins/ipam/host-local/backend"
)

type IPAllocator struct {
	netName string
	ipRange Range
	store   backend.Store
	rangeID string // Used for tracking last reserved ip
}

type RangeIter struct {
	low   net.IP
	high  net.IP
	cur   net.IP
	start net.IP
}

func NewIPAllocator(netName string, r Range, store backend.Store) *IPAllocator {
	// The range name (last allocated ip suffix) is just the base64
	// encoding of the bytes of the first IP
	rangeID := base64.URLEncoding.EncodeToString(r.RangeStart)

	return &IPAllocator{
		netName: netName,
		ipRange: r,
		store:   store,
		rangeID: rangeID,
	}
}

// Get alocates an IP
func (a *IPAllocator) Get(id string, requestedIP net.IP) (*current.IPConfig, error) {
	a.store.Lock()
	defer a.store.Unlock()

	gw := a.ipRange.Gateway

	var reservedIP net.IP

	if requestedIP != nil {
		if gw != nil && gw.Equal(requestedIP) {
			return nil, fmt.Errorf("requested IP must differ from gateway IP")
		}

		if err := a.ipRange.IPInRange(requestedIP); err != nil {
			return nil, err
		}

		reserved, err := a.store.Reserve(id, requestedIP, a.rangeID)
		if err != nil {
			return nil, err
		}
		if !reserved {
			return nil, fmt.Errorf("requested IP address %q is not available in network: %s %s", requestedIP, a.netName, (*net.IPNet)(&a.ipRange.Subnet).String())
		}
		reservedIP = requestedIP

	} else {
		iter, err := a.GetIter()
		if err != nil {
			return nil, err
		}
		for {
			cur := iter.Next()
			if cur == nil {
				break
			}

			// don't allocate gateway IP
			if gw != nil && cur.Equal(gw) {
				continue
			}

			reserved, err := a.store.Reserve(id, cur, a.rangeID)
			if err != nil {
				return nil, err
			}

			if reserved {
				reservedIP = cur
				break
			}
		}
	}

	if reservedIP == nil {
		return nil, fmt.Errorf("no IP addresses available in network: %s %s", a.netName, (*net.IPNet)(&a.ipRange.Subnet).String())
	}
	version := "4"
	if reservedIP.To4() == nil {
		version = "6"
	}

	return &current.IPConfig{
		Version: version,
		Address: net.IPNet{IP: reservedIP, Mask: a.ipRange.Subnet.Mask},
		Gateway: gw,
	}, nil
}

// Release clears all IPs allocated for the container with given ID
func (a *IPAllocator) Release(id string) error {
	a.store.Lock()
	defer a.store.Unlock()

	return a.store.ReleaseByID(id)
}

// GetIter encapsulates the strategy for this allocator.
// We use a round-robin strategy, attempting to evenly use the whole subnet.
// More specifically, a crash-looping container will not see the same IP until
// the entire range has been run through.
// We may wish to consider avoiding recently-released IPs in the future.
func (a *IPAllocator) GetIter() (*RangeIter, error) {
	i := RangeIter{
		low:  a.ipRange.RangeStart,
		high: a.ipRange.RangeEnd,
	}

	// Round-robin by trying to allocate from the last reserved IP + 1
	startFromLastReservedIP := false

	// We might get a last reserved IP that is wrong if the range indexes changed.
	// This is not critical, we just lose round-robin this one time.
	lastReservedIP, err := a.store.LastReservedIP(a.rangeID)
	if err != nil && !os.IsNotExist(err) {
		log.Printf("Error retrieving last reserved ip: %v", err)
	} else if lastReservedIP != nil {
		startFromLastReservedIP = a.ipRange.IPInRange(lastReservedIP) == nil
	}

	if startFromLastReservedIP {
		if i.high.Equal(lastReservedIP) {
			i.start = i.low
		} else {
			i.start = ip.NextIP(lastReservedIP)
		}
	} else {
		i.start = a.ipRange.RangeStart
	}
	return &i, nil
}

// Next returns the next IP in the iterator, or nil if end is reached
func (i *RangeIter) Next() net.IP {
	// If we're at the beginning, time to start
	if i.cur == nil {
		i.cur = i.start
		return i.cur
	}
	//  we returned .high last time, since we're inclusive
	if i.cur.Equal(i.high) {
		i.cur = i.low
	} else {
		i.cur = ip.NextIP(i.cur)
	}

	// If we've looped back to where we started, exit
	if i.cur.Equal(i.start) {
		return nil
	}

	return i.cur
}
