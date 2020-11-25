package main

import (
	"flag"
	"fmt"
	"io"
	"net"
)

func main() {
	target := flag.String("target", "", "the server address")
	payload := flag.String("message", "", "the message to send to the server")
	protocol := flag.String("protocol", "tcp", "the protocol to use with the server [udp,tcp], default tcp")
	flag.Parse()

	if *target == "" || *payload == "" {
		flag.Usage()
		panic("invalid arguments")
	}

	switch *protocol {
	case "tcp":
		connectTCP(*target, *payload)
	case "udp":
		connectUDP(*target, *payload)
	default:
		panic("invalid protocol")
	}
}

func connectTCP(target, payload string) {
	conn, err := net.Dial("tcp", target)
	if err != nil {
		panic(fmt.Sprintf("Failed to open connection to [%s] %v", target, err))
	}
	defer conn.Close()

	_, err = conn.Write([]byte(payload))
	if err != nil {
		panic("Failed to send payload")
	}
	_, err = conn.Write([]byte("\n"))
	if err != nil {
		panic("Failed to send payload")
	}
	buf := make([]byte, 1024)
	for {
		n, err := conn.Read(buf)
		fmt.Print(string(buf[:n]))
		if err == io.EOF {
			break
		}
		if err != nil {
			panic("Failed to read from socket")
		}
	}
}

// UDP uses a constant source port to trigger conntrack problems
func connectUDP(target, payload string) {
	LocalAddr, err := net.ResolveUDPAddr("udp", ":54321")
	if err != nil {
		panic(fmt.Sprintf("Failed to resolve UDP local address on port 54321 %v", err))
	}
	RemoteAddr, err := net.ResolveUDPAddr("udp", target)
	if err != nil {
		panic(fmt.Sprintf("Failed to resolve UDP remote address [%s] %v", target, err))
	}
	conn, err := net.DialUDP("udp", LocalAddr, RemoteAddr)
	if err != nil {
		panic(fmt.Sprintf("Failed to open connection to [%s] %v", target, err))
	}
	defer conn.Close()

	_, err = conn.Write([]byte(payload))
	if err != nil {
		panic("Failed to send payload")
	}
	_, err = conn.Write([]byte("\n"))
	if err != nil {
		panic("Failed to send payload")
	}

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		panic("Failed to read from socket")
	}
	fmt.Print(string(buf[:n]))
}
