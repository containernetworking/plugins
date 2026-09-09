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
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/plugins/plugins/ipam/host-local/backend"
)

const (
	lastIPFilePrefix = "last_reserved_ip."
	LineBreak        = "\r\n"
	// lockFileName is the file NewFileLock creates when it is handed a
	// directory. It shares the data dir with the reservations, so GC has to know
	// its name in order not to delete it.
	lockFileName = "lock"
)

var defaultDataDir = "/var/lib/cni/networks"

// Store is a simple disk-backed store that creates one file per IP
// address in a given directory. The contents of the file are the container ID.
type Store struct {
	*FileLock
	dataDir string
}

// Store implements the Store interface
var _ backend.Store = &Store{}

func New(network, dataDir string) (*Store, error) {
	if dataDir == "" {
		dataDir = defaultDataDir
	}
	dir := filepath.Join(dataDir, network)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}

	lk, err := NewFileLock(dir)
	if err != nil {
		return nil, err
	}
	return &Store{lk, dir}, nil
}

func (s *Store) Reserve(id string, ifname string, ip net.IP, rangeID string) (bool, error) {
	fname := GetEscapedPath(s.dataDir, ip.String())

	f, err := os.OpenFile(fname, os.O_RDWR|os.O_EXCL|os.O_CREATE, 0o600)
	if os.IsExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if _, err := f.WriteString(strings.TrimSpace(id) + LineBreak + ifname); err != nil {
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
	err = os.WriteFile(ipfile, []byte(ip.String()), 0o600)
	if err != nil {
		return false, err
	}
	return true, nil
}

// LastReservedIP returns the last reserved IP if exists
func (s *Store) LastReservedIP(rangeID string) (net.IP, error) {
	ipfile := GetEscapedPath(s.dataDir, lastIPFilePrefix+rangeID)
	data, err := os.ReadFile(ipfile)
	if err != nil {
		return nil, err
	}
	return net.ParseIP(string(data)), nil
}

func (s *Store) FindByKey(match string) (bool, error) {
	found := false

	err := filepath.Walk(s.dataDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		if strings.TrimSpace(string(data)) == match {
			found = true
		}
		return nil
	})
	return found, err
}

func (s *Store) FindByID(id string, ifname string) bool {
	s.Lock()
	defer s.Unlock()

	match := strings.TrimSpace(id) + LineBreak + ifname
	found, err := s.FindByKey(match)

	// Match anything created by this id
	if !found && err == nil {
		match := strings.TrimSpace(id)
		found, _ = s.FindByKey(match)
	}

	return found
}

func (s *Store) ReleaseByKey(match string) (bool, error) {
	found := false
	err := filepath.Walk(s.dataDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		if strings.TrimSpace(string(data)) == match {
			if err := os.Remove(path); err != nil {
				return nil
			}
			found = true
		}
		return nil
	})
	return found, err
}

// N.B. This function eats errors to be tolerant and
// release as much as possible
func (s *Store) ReleaseByID(id string, ifname string) error {
	match := strings.TrimSpace(id) + LineBreak + ifname
	found, err := s.ReleaseByKey(match)

	// For backwards compatibility, look for files written by a previous version
	if !found && err == nil {
		match := strings.TrimSpace(id)
		_, err = s.ReleaseByKey(match)
	}
	return err
}

// GC releases every reservation whose attachment is absent from attachments,
// which the runtime supplies as the complete set of attachments it still
// considers live. It is how a reservation leaked by a DEL that never arrived
// gets reclaimed.
//
// Like ReleaseByID this is deliberately tolerant of per-file errors: releasing
// as much as possible is more useful than stopping at the first unreadable
// reservation.
func (s *Store) GC(attachments []types.GCAttachment) error {
	s.Lock()
	defer s.Unlock()

	valid := make(map[string]struct{}, len(attachments))
	// Reservations written before the ifname was recorded hold only a container
	// ID, so keep a second set to match those. Without it the first GC after an
	// upgrade would release every pre-upgrade allocation.
	validLegacy := make(map[string]struct{}, len(attachments))
	for _, a := range attachments {
		id := strings.TrimSpace(a.ContainerID)
		valid[id+LineBreak+a.IfName] = struct{}{}
		validLegacy[id] = struct{}{}
	}

	entries, err := os.ReadDir(s.dataDir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if e.IsDir() || !isReservation(e.Name()) {
			continue
		}
		path := filepath.Join(s.dataDir, e.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		key := strings.TrimSpace(string(data))
		if _, ok := valid[key]; ok {
			continue
		}
		if !strings.Contains(key, LineBreak) {
			if _, ok := validLegacy[key]; ok {
				continue
			}
		}
		_ = os.Remove(path)
	}
	return nil
}

// isReservation reports whether a file in a network's data dir is an address
// reservation. The lock and the per-range last_reserved_ip markers share that
// directory and have to survive a GC.
func isReservation(name string) bool {
	return name != lockFileName && !strings.HasPrefix(name, lastIPFilePrefix)
}

// GetByID returns the IPs which have been allocated to the specific ID
func (s *Store) GetByID(id string, ifname string) []net.IP {
	var ips []net.IP

	match := strings.TrimSpace(id) + LineBreak + ifname
	// matchOld for backwards compatibility
	matchOld := strings.TrimSpace(id)

	// walk through all ips in this network to get the ones which belong to a specific ID
	_ = filepath.Walk(s.dataDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		if strings.TrimSpace(string(data)) == match || strings.TrimSpace(string(data)) == matchOld {
			_, ipString := filepath.Split(path)
			if ip := net.ParseIP(ipString); ip != nil {
				ips = append(ips, ip)
			}
		}
		return nil
	})

	return ips
}

func GetEscapedPath(dataDir string, fname string) string {
	if runtime.GOOS == "windows" {
		fname = strings.ReplaceAll(fname, ":", "_")
	}
	return filepath.Join(dataDir, fname)
}
