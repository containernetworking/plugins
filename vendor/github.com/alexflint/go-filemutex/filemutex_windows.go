// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package filemutex

import (
	"golang.org/x/sys/windows"
)

// FileMutex is similar to sync.RWMutex, but also synchronizes across processes.
// This implementation is based on flock syscall.
type FileMutex struct {
	fd windows.Handle
}

func New(filename string) (*FileMutex, error) {
	fd, err := windows.CreateFile(&(windows.StringToUTF16(filename)[0]), windows.GENERIC_READ|windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_ALWAYS, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return nil, err
	}
	return &FileMutex{fd: fd}, nil
}

func (m *FileMutex) TryLock() error {
	if err := windows.LockFileEx(m.fd, windows.LOCKFILE_FAIL_IMMEDIATELY|windows.LOCKFILE_EXCLUSIVE_LOCK, 0, 1, 0, &windows.Overlapped{}); err != nil {
		if errno, ok := err.(windows.Errno); ok {
			if errno == windows.ERROR_LOCK_VIOLATION {
				return AlreadyLocked
			}
		}
		return err
	}
	return nil
}

func (m *FileMutex) Lock() error {
	return windows.LockFileEx(m.fd, windows.LOCKFILE_EXCLUSIVE_LOCK, 0, 1, 0, &windows.Overlapped{})
}

func (m *FileMutex) Unlock() error {
	return windows.UnlockFileEx(m.fd, 0, 1, 0, &windows.Overlapped{})
}

func (m *FileMutex) RLock() error {
	return windows.LockFileEx(m.fd, 0, 0, 1, 0, &windows.Overlapped{})
}

func (m *FileMutex) RUnlock() error {
	return windows.UnlockFileEx(m.fd, 0, 1, 0, &windows.Overlapped{})
}

// Close unlocks the lock and closes the underlying file descriptor.
func (m *FileMutex) Close() error {
	// See comment section of https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-lockfileex
	// It's recommended to unlock a file explicitly before closing in order to
	// avoid delays, but all locks are definitly unlocked when closing a file.
	// So any unlocking error can be ignored.
	_ = windows.UnlockFileEx(m.fd, 0, 1, 0, &windows.Overlapped{})

	return windows.Close(m.fd)
}
