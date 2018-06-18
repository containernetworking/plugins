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

package disk

import (
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/containernetworking/plugins/plugins/ipam/host-local/backend"
)

const lastIPFilePrefix = "last_reserved_ip."

var defaultDataDir = "/var/lib/cni/networks"

// Store is a simple disk-backed store that creates one file per IP
// address in a given directory. The contents of the file are the container ID.
type Store struct {
	*FileLock
	dataDir string
}

// Store implements the Store interface
var _ backend.Store = &Store{}

// New creates a new store
func New(network, dataDir string) (*Store, error) {
	if dataDir == "" {
		dataDir = defaultDataDir
	}
	dir := filepath.Join(dataDir, network)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, err
	}

	lk, err := NewFileLock(dir)
	if err != nil {
		return nil, err
	}
	return &Store{lk, dir}, nil
}

// Reserve attempts to claim an ip in the name of a container with the given id.
// The store should be locked before calling this.
func (s *Store) Reserve(id backend.Key, ip net.IP, rangeID string) (bool, error) {
	fname := GetEscapedPath(s.dataDir, ip.String())

	f, err := os.OpenFile(fname, os.O_RDWR|os.O_EXCL|os.O_CREATE, 0644)
	if os.IsExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if _, err := f.Write(WriteKey(&id)); err != nil {
		f.Close()
		os.Remove(f.Name())
		return false, err
	}
	if err := f.Close(); err != nil {
		os.Remove(f.Name())
		return false, err
	}
	// store the reserved ip in lastIPFile
	ipfile := GetEscapedPath(s.dataDir, lastIPFilePrefix+rangeID)
	err = ioutil.WriteFile(ipfile, []byte(ip.String()), 0644)
	if err != nil {
		return false, err
	}
	return true, nil
}

// LastReservedIP returns the last reserved IP if exists
func (s *Store) LastReservedIP(rangeID string) (net.IP, error) {
	ipfile := GetEscapedPath(s.dataDir, lastIPFilePrefix+rangeID)
	data, err := ioutil.ReadFile(ipfile)
	if err != nil {
		return nil, err
	}
	return net.ParseIP(string(data)), nil
}

// Release will mark a given ip as released, regardless of which container holds it.
func (s *Store) Release(ip net.IP) error {
	return os.Remove(GetEscapedPath(s.dataDir, ip.String()))
}

// ReleaseByID releases all IPs held by a container of the given id.
// N.B. This function eats errors to be tolerant and
// release as much as possible
//
func (s *Store) ReleaseByID(id backend.Key) error {
	err := s.walkReservations(func(path string, _ net.IP, b []byte) error {
		match, err := Matches(&id, b)
		if err != nil {
			fmt.Fprintf(os.Stderr, "WARN: host-local: Failed to parse ip reservation file %s: %v", path, err)
			return nil
		}
		if match {
			err := os.Remove(path)
			if err != nil {
				fmt.Fprintf(os.Stderr, "WARN host-local: failed to remove ip reservation file %s: %v", path, err)
			}
		}
		return nil
	})
	return err
}

// GetByID returns all IPs reserved by a given container ID
func (s *Store) GetByID(id backend.Key) ([]net.IP, error) {
	out := []net.IP{}
	err := s.walkReservations(func(path string, ip net.IP, b []byte) error {
		matches, err := Matches(&id, b)
		if err != nil {
			fmt.Fprintf(os.Stderr, "WARN: host-local: Failed to parse ip reservation file %s: %v", path, err)
			return nil
		}

		if matches {
			out = append(out, ip)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// walkReservations executes f(ip, keyBytes) for every reservation
func (s *Store) walkReservations(f func(string, net.IP, []byte) error) error {
	err := filepath.Walk(s.dataDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		ip := UnescapePath(info.Name())
		if len(ip) == 0 { // not a reservation file
			return nil
		}

		b, err := ioutil.ReadFile(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "WARN: host-local: Failed to read ip reservation file %s: %v", path, err)
			return nil
		}

		return f(path, ip, b)
	})
	return err
}

func GetEscapedPath(dataDir string, fname string) string {
	if runtime.GOOS == "windows" {
		fname = strings.Replace(fname, ":", "_", -1)
	}
	return filepath.Join(dataDir, fname)
}

func UnescapePath(fname string) net.IP {
	if runtime.GOOS == "windows" {
		fname = strings.Replace(fname, "_", ":", -1)
	}
	return net.ParseIP(fname)
}
