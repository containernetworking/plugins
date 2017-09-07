// Echosvr is a simple TCP echo server
//
// It prints its listen address on stdout
//    127.0.0.1:xxxxx
//  A test should wait for this line, parse it
//  and may then attempt to connect.
package main

import (
	"fmt"
	"net"
)

func main() {
	listener, err := net.Listen("tcp", ":")
	if err != nil {
		panic(err)
	}
	_, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		panic(err)
	}
	fmt.Printf("127.0.0.1:%s\n", port)
	for {
		conn, err := listener.Accept()
		if err != nil {
			panic(err)
		}
		go handleConnection(conn)
	}
}

func handleConnection(conn net.Conn) {
	buf := make([]byte, 512)
	nBytesRead, _ := conn.Read(buf)
	conn.Write(buf[0:nBytesRead])
	conn.Close()
}
