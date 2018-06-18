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

package backend

import "net"

// Key is the primary key for the store
type Key struct {
	ID string // the container ID
	IF string // The container interface name
}

// Equals checks for key equality
func (k *Key) Equals(k1 *Key) bool {
	if k == nil && k1 == nil {
		return true
	}
	if k == nil {
		return false
	}
	if k1 == nil {
		return false
	}

	return k.ID == k1.ID && k.IF == k1.IF
}

type Store interface {
	Lock() error
	Unlock() error
	Close() error
	Reserve(key Key, ip net.IP, rangeID string) (bool, error)
	LastReservedIP(rangeID string) (net.IP, error)
	Release(ip net.IP) error
	ReleaseByID(id Key) error
	GetByID(id Key) ([]net.IP, error)
}
