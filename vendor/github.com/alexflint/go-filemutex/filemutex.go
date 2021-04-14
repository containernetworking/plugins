package filemutex

import "errors"

var AlreadyLocked = errors.New("lock already acquired")
