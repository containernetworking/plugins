// Copyright 2016 CNI authors
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

package hwaddr

import (
	"crypto/rand"
	"net"
)

// The first 24 bits of the MAC represent the Organizationally Unique Identifier (OUI),
// and the first byte of the MAC address has two special bits.
// 1. The least-significant bit: 0 for unicast and 1 for multicast
// 2. The second-least-significant bit: 0 for globally unique and 1 for locally administered
// Since MAC address for container interfaces is locally administered and unicast, so we can
// fix the two LSb of MSB to 10 and use any values for other bits. This will avoid any conflicts
// with public OUIs.
// We use 02:58:00 for CNI official OUI here.
var cniOUI = []byte{0x02, 0x58, 0x00}

// GenerateMAC will generate MAC addresses with fixed first 24 bits (CNI OUI), and the last 24 bits
// will be random, so there are at most 16777216(2^24) different addresses.
// To avoid MAC address collision as much as possible, this function is suggested to be used within
// the limitation that each subnet should contain no more 1024(2^10) using IP addresses.
// For example, a subnet whose prefix is greater or equal than 22 is safe to use this function
// as MAC address generator.
func GenerateMAC() net.HardwareAddr {
	hw := make(net.HardwareAddr, 6)
	copy(hw[:3], cniOUI)
	_, _ = rand.Read(hw[3:])
	return hw
}
