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

package main

import "fmt"
import "syscall"
import "unsafe"

const (
	SIOCETHTOOL = 0x8946 // linux/sockios.h
	IFNAMSIZ    = 16     // linux/if.h

	//linux/ethtool.h
	ETHTOOL_GTXCSUM = 0x00000016 // Get TX hw csum enable (ethtool_value)
	ETHTOOL_STXCSUM = 0x00000017 // Set TX hw csum enable (ethtool_value)
	ETHTOOL_GTSO    = 0x0000001e // Get TSO enable (ethtool_value)
	ETHTOOL_STSO    = 0x0000001f // Set TSO enable (ethtool_value)
	ETHTOOL_GGSO    = 0x00000023 // Get GSO enable (ethtool_value)
	ETHTOOL_SGSO    = 0x00000024 // Set GSO enable (ethtool_value)
)

// linux/if.h 'struct ifreq'
type IFReqData struct {
	Name [IFNAMSIZ]byte
	Data uintptr
}

// linux/ethtool.h 'struct ethtool_value'
type EthtoolValue struct {
	Cmd  uint32
	Data uint32
}

func sendIoctl(fd int, argp uintptr) error {
	_, _, errno := syscall.RawSyscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(SIOCETHTOOL), argp)
	if errno != 0 {
		return errno
	}
	return nil
}

// Disable TX checksum offload on specified interface
func EthtoolTxCheckSumOff(name string) error {
	if len(name)+1 > IFNAMSIZ {
		return fmt.Errorf("name too long")
	}

	socket, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err != nil {
		return err
	}
	defer syscall.Close(socket)

	// Request current value
	value := EthtoolValue{Cmd: ETHTOOL_GTXCSUM}
	request := IFReqData{Data: uintptr(unsafe.Pointer(&value))}
	copy(request.Name[:], name)

	if err := sendIoctl(socket, uintptr(unsafe.Pointer(&request))); err != nil {
		return err
	}
	if value.Data == 0 { // if already off, don't try to change
		return nil
	}

	value = EthtoolValue{ETHTOOL_STXCSUM, 0}
	return sendIoctl(socket, uintptr(unsafe.Pointer(&request)))
}

// Enable TX checksum offload on specified interface
func EthtoolTxCheckSumOn(name string) error {
	if len(name)+1 > IFNAMSIZ {
		return fmt.Errorf("name too long")
	}

	socket, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err != nil {
		return err
	}
	defer syscall.Close(socket)

	// Request current value
	value := EthtoolValue{Cmd: ETHTOOL_GTXCSUM}
	request := IFReqData{Data: uintptr(unsafe.Pointer(&value))}
	copy(request.Name[:], name)

	if err := sendIoctl(socket, uintptr(unsafe.Pointer(&request))); err != nil {
		return err
	}
	if value.Data == 1 { // if already on, don't try to change
		return nil
	}

	value = EthtoolValue{ETHTOOL_STXCSUM, 1}
	return sendIoctl(socket, uintptr(unsafe.Pointer(&request)))
}

// Get TX checksum offload on specified interface
func GetEthtoolTxCheckSum(name string) (bool, error) {
	if len(name)+1 > IFNAMSIZ {
		return false, fmt.Errorf("name too long")
	}

	socket, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err != nil {
		return false, err
	}
	defer syscall.Close(socket)

	// Request current value
	value := EthtoolValue{Cmd: ETHTOOL_GTXCSUM}
	request := IFReqData{Data: uintptr(unsafe.Pointer(&value))}
	copy(request.Name[:], name)

	if err := sendIoctl(socket, uintptr(unsafe.Pointer(&request))); err != nil {
		return false, err
	}
	return value.Data == 1, nil
}

func EthtoolTsoOff(name string) error {
	if len(name)+1 > IFNAMSIZ {
		return fmt.Errorf("name too long")
	}

	socket, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err != nil {
		return err
	}
	defer syscall.Close(socket)

	// Request current value
	value := EthtoolValue{Cmd: ETHTOOL_GTSO}
	request := IFReqData{Data: uintptr(unsafe.Pointer(&value))}
	copy(request.Name[:], name)

	if err := sendIoctl(socket, uintptr(unsafe.Pointer(&request))); err != nil {
		return err
	}
	if value.Data == 0 { // if already off, don't try to change
		return nil
	}

	value = EthtoolValue{ETHTOOL_STSO, 0}
	return sendIoctl(socket, uintptr(unsafe.Pointer(&request)))
}

func EthtoolTsoOn(name string) error {
	if len(name)+1 > IFNAMSIZ {
		return fmt.Errorf("name too long")
	}

	socket, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err != nil {
		return err
	}
	defer syscall.Close(socket)

	// Request current value
	value := EthtoolValue{Cmd: ETHTOOL_GTSO}
	request := IFReqData{Data: uintptr(unsafe.Pointer(&value))}
	copy(request.Name[:], name)

	if err := sendIoctl(socket, uintptr(unsafe.Pointer(&request))); err != nil {
		return err
	}
	if value.Data == 1 { // if already on, don't try to change
		return nil
	}

	value = EthtoolValue{ETHTOOL_STSO, 1}
	return sendIoctl(socket, uintptr(unsafe.Pointer(&request)))
}

func GetEthtoolTso(name string) (bool, error) {
	if len(name)+1 > IFNAMSIZ {
		return false, fmt.Errorf("name too long")
	}

	socket, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err != nil {
		return false, err
	}
	defer syscall.Close(socket)

	// Request current value
	value := EthtoolValue{Cmd: ETHTOOL_GTSO}
	request := IFReqData{Data: uintptr(unsafe.Pointer(&value))}
	copy(request.Name[:], name)

	if err := sendIoctl(socket, uintptr(unsafe.Pointer(&request))); err != nil {
		return false, err
	}
	return value.Data == 1, nil
}

func EthtoolGsoOff(name string) error {
	if len(name)+1 > IFNAMSIZ {
		return fmt.Errorf("name too long")
	}

	socket, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err != nil {
		return err
	}
	defer syscall.Close(socket)

	// Request current value
	value := EthtoolValue{Cmd: ETHTOOL_GGSO}
	request := IFReqData{Data: uintptr(unsafe.Pointer(&value))}
	copy(request.Name[:], name)

	if err := sendIoctl(socket, uintptr(unsafe.Pointer(&request))); err != nil {
		return err
	}
	if value.Data == 0 { // if already off, don't try to change
		return nil
	}

	value = EthtoolValue{ETHTOOL_SGSO, 0}
	return sendIoctl(socket, uintptr(unsafe.Pointer(&request)))
}

func EthtoolGsoOn(name string) error {
	if len(name)+1 > IFNAMSIZ {
		return fmt.Errorf("name too long")
	}

	socket, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err != nil {
		return err
	}
	defer syscall.Close(socket)

	// Request current value
	value := EthtoolValue{Cmd: ETHTOOL_GGSO}
	request := IFReqData{Data: uintptr(unsafe.Pointer(&value))}
	copy(request.Name[:], name)

	if err := sendIoctl(socket, uintptr(unsafe.Pointer(&request))); err != nil {
		return err
	}
	if value.Data == 1 { // if already on, don't try to change
		return nil
	}

	value = EthtoolValue{ETHTOOL_SGSO, 1}
	return sendIoctl(socket, uintptr(unsafe.Pointer(&request)))
}

func GetEthtoolGso(name string) (bool, error) {
	if len(name)+1 > IFNAMSIZ {
		return false, fmt.Errorf("name too long")
	}

	socket, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err != nil {
		return false, err
	}
	defer syscall.Close(socket)

	// Request current value
	value := EthtoolValue{Cmd: ETHTOOL_GGSO}
	request := IFReqData{Data: uintptr(unsafe.Pointer(&value))}
	copy(request.Name[:], name)

	if err := sendIoctl(socket, uintptr(unsafe.Pointer(&request))); err != nil {
		return false, err
	}
	return value.Data == 1, nil
}
