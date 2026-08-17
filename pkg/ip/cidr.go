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

package ip

import (
	"math/big"
	"net"
)

// NextIP returns IP incremented by 1, or nil if IP is invalid or already the
// last address in its family.
func NextIP(ip net.IP) net.IP {
	normalizedIP := normalizeIP(ip)
	if normalizedIP == nil {
		return nil
	}

	i := ipToInt(normalizedIP)
	return intToIP(i.Add(i, big.NewInt(1)), len(normalizedIP) == net.IPv6len)
}

// PrevIP returns IP decremented by 1, or nil if IP is invalid or already the
// first address in its family.
func PrevIP(ip net.IP) net.IP {
	normalizedIP := normalizeIP(ip)
	if normalizedIP == nil {
		return nil
	}

	i := ipToInt(normalizedIP)
	return intToIP(i.Sub(i, big.NewInt(1)), len(normalizedIP) == net.IPv6len)
}

// Cmp compares two IPs, returning the usual ordering:
// a < b : -1
// a == b : 0
// a > b : 1
// incomparable : -2
func Cmp(a, b net.IP) int {
	normalizedA := normalizeIP(a)
	normalizedB := normalizeIP(b)

	if len(normalizedA) == len(normalizedB) && len(normalizedA) != 0 {
		return ipToInt(normalizedA).Cmp(ipToInt(normalizedB))
	}

	return -2
}

func ipToInt(ip net.IP) *big.Int {
	return big.NewInt(0).SetBytes(ip)
}

func intToIP(i *big.Int, isIPv6 bool) net.IP {
	// big.Int.Bytes returns the absolute value, so a value that went below the
	// first address of its family would otherwise come back as a positive IP.
	if i.Sign() < 0 {
		return nil
	}

	ipLen := net.IPv4len
	if isIPv6 {
		ipLen = net.IPv6len
	}

	intBytes := i.Bytes()
	// The value overflowed past the last address of its family.
	if len(intBytes) > ipLen {
		return nil
	}

	// Always return the family's fixed width. Choosing the length from the
	// minimal big.Int encoding would turn a low IPv6 value whose leading bytes
	// are zero into a 4-byte IPv4 address.
	out := make(net.IP, ipLen)
	copy(out[ipLen-len(intBytes):], intBytes)
	return out
}

// normalizeIP will normalize IP by family,
// IPv4 : 4-byte form
// IPv6 : 16-byte form
// others : nil
func normalizeIP(ip net.IP) net.IP {
	if ipTo4 := ip.To4(); ipTo4 != nil {
		return ipTo4
	}
	return ip.To16()
}

// Network masks off the host portion of the IP, if IPNet is invalid,
// return nil
func Network(ipn *net.IPNet) *net.IPNet {
	if ipn == nil {
		return nil
	}

	maskedIP := ipn.IP.Mask(ipn.Mask)
	if maskedIP == nil {
		return nil
	}

	return &net.IPNet{
		IP:   maskedIP,
		Mask: ipn.Mask,
	}
}
