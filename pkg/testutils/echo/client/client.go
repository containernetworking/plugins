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
	flag.Parse()

	if *target == "" || *payload == "" {
		flag.Usage()
		panic("invalid arguments")
	}
	conn, err := net.Dial("tcp", *target)
	if err != nil {
		panic(fmt.Sprintf("Failed to open connection to [%s] %v", *target, err))
	}
	defer conn.Close()

	_, err = conn.Write([]byte(*payload))
	if err != nil {
		panic("Failed to send payload")
	}
	_, err = conn.Write([]byte("\n"))
	if err != nil {
		panic("Failed to send payload")
	}

	buf := make([]byte, 4)
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
