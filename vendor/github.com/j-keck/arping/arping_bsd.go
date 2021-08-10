// +build darwin freebsd openbsd

package arping

import (
	"errors"
	"fmt"
	"net"
	"os"
	"runtime"
	"syscall"
	"time"
)

type BsdSocket struct {
	bpf    *os.File
	bpfFd  int
	buflen int
}

var bpfArpFilter = []syscall.BpfInsn{
	// make sure this is an arp packet
	*syscall.BpfStmt(syscall.BPF_LD+syscall.BPF_H+syscall.BPF_ABS, 12),
	*syscall.BpfJump(syscall.BPF_JMP+syscall.BPF_JEQ+syscall.BPF_K, 0x0806, 0, 1),
	// if we passed all the tests, ask for the whole packet.
	*syscall.BpfStmt(syscall.BPF_RET+syscall.BPF_K, -1),
	// otherwise, drop it.
	*syscall.BpfStmt(syscall.BPF_RET+syscall.BPF_K, 0),
}

func initialize(iface net.Interface) (s *BsdSocket, err error) {
	s = &BsdSocket{}
	verboseLog.Println("search available /dev/bpfX")
	for i := 0; i <= 10; i++ {
		bpfPath := fmt.Sprintf("/dev/bpf%d", i)
		s.bpf, err = os.OpenFile(bpfPath, os.O_RDWR, 0666)
		if err != nil {
			verboseLog.Printf("  open failed: %s - %s\n", bpfPath, err.Error())
		} else {
			verboseLog.Printf("  open success: %s\n", bpfPath)
			break
		}
	}
	s.bpfFd = int(s.bpf.Fd())
	if s.bpfFd == -1 {
		return s, errors.New("unable to open /dev/bpfX")
	}

	if err := syscall.SetBpfInterface(s.bpfFd, iface.Name); err != nil {
		return s, err
	}

	if err := syscall.SetBpfImmediate(s.bpfFd, 1); err != nil {
		return s, err
	}

	s.buflen, err = syscall.BpfBuflen(s.bpfFd)
	if err != nil {
		return s, err
	}

	if err := syscall.SetBpf(s.bpfFd, bpfArpFilter); err != nil {
		return s, err
	}

	if err := syscall.FlushBpf(s.bpfFd); err != nil {
		return s, err
	}

	return s, nil
}

func (s *BsdSocket) send(request arpDatagram) (time.Time, error) {
	_, err := syscall.Write(s.bpfFd, request.MarshalWithEthernetHeader())
	return time.Now(), err
}

func (s *BsdSocket) receive() (arpDatagram, time.Time, error) {
	buffer := make([]byte, s.buflen)
	n, err := syscall.Read(s.bpfFd, buffer)
	if err != nil {
		return arpDatagram{}, time.Now(), err
	}

	//
	// FreeBSD uses a different bpf header (bh_tstamp differ in it's size)
	// https://www.freebsd.org/cgi/man.cgi?bpf(4)#BPF_HEADER
	//
	var bpfHdrLength int
	if runtime.GOOS == "freebsd" {
		bpfHdrLength = 26
	} else {
		bpfHdrLength = 18
	}

	// skip bpf header + 14 bytes ethernet header
	var hdrLength = bpfHdrLength + 14

	return parseArpDatagram(buffer[hdrLength:n]), time.Now(), nil
}

func (s *BsdSocket) deinitialize() error {
	return s.bpf.Close()
}
