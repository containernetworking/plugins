// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build darwin dragonfly freebsd linux netbsd openbsd solaris

package filemutex

import "golang.org/x/sys/unix"

const (
	mkdirPerm = 0750
)

// FileMutex is similar to sync.RWMutex, but also synchronizes across processes.
// This implementation is based on flock syscall.
type FileMutex struct {
	fd int
}

func New(filename string) (*FileMutex, error) {
	fd, err := unix.Open(filename, unix.O_CREAT|unix.O_RDONLY, mkdirPerm)
	if err != nil {
		return nil, err
	}
	return &FileMutex{fd: fd}, nil
}

func (m *FileMutex) Lock() error {
	return unix.Flock(m.fd, unix.LOCK_EX)
}

func (m *FileMutex) TryLock() error {
	if err := unix.Flock(m.fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		if errno, ok := err.(unix.Errno); ok {
			if errno == unix.EWOULDBLOCK {
				return AlreadyLocked
			}
		}
		return err
	}
	return nil
}

func (m *FileMutex) Unlock() error {
	return unix.Flock(m.fd, unix.LOCK_UN)
}

func (m *FileMutex) RLock() error {
	return unix.Flock(m.fd, unix.LOCK_SH)
}

func (m *FileMutex) RUnlock() error {
	return unix.Flock(m.fd, unix.LOCK_UN)
}

// Close unlocks the lock and closes the underlying file descriptor.
func (m *FileMutex) Close() error {
	if err := unix.Flock(m.fd, unix.LOCK_UN); err != nil {
		return err
	}
	return unix.Close(m.fd)
}
