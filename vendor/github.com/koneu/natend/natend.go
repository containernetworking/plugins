// Package natend implements a native endian ByteOrder for use with the encoding/binary package or similar interfaces.
package natend

import "unsafe"

// NativeEndian is the native-endian implementation of ByteOrder.
var NativeEndian nativeEndian

type nativeEndian struct{}

func (nativeEndian) Uint16(b []byte) uint16 {
	_ = b[1]
	return *(*uint16)(unsafe.Pointer(&b[0]))
}

func (nativeEndian) Uint32(b []byte) uint32 {
	_ = b[3]
	return *(*uint32)(unsafe.Pointer(&b[0]))
}

func (nativeEndian) Uint64(b []byte) uint64 {
	_ = b[7]
	return *(*uint64)(unsafe.Pointer(&b[0]))
}

func (nativeEndian) PutUint16(b []byte, v uint16) {
	_ = b[1]
	*(*uint16)(unsafe.Pointer(&b[0])) = v
}

func (nativeEndian) PutUint32(b []byte, v uint32) {
	_ = b[3]
	*(*uint32)(unsafe.Pointer(&b[0])) = v
}

func (nativeEndian) PutUint64(b []byte, v uint64) {
	_ = b[7]
	*(*uint64)(unsafe.Pointer(&b[0])) = v
}

func (nativeEndian) String() string { return "NativeEndian" }
func (nativeEndian) GoString() string { return "natend.NativeEndian" }
