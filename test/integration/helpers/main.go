// Command helpers generates test traffic for the integration tests.
package main

import (
	"fmt"
	"io"
	"net"
	"os"
	"time"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: helpers tcp-server|udp-server|tcp-client|udp-sendto|hold ADDR [READY_FILE]")
		os.Exit(2)
	}
	cmd, addr := os.Args[1], os.Args[2]
	ready := ""
	if len(os.Args) > 3 {
		ready = os.Args[3]
	}
	var err error
	switch cmd {
	case "tcp-server":
		err = tcpServer(addr, ready)
	case "udp-server":
		err = udpServer(addr, ready)
	case "tcp-client":
		err = tcpClient(addr)
	case "udp-sendto":
		err = udpSendto(addr)
	case "hold":
		err = hold(addr, ready)
	default:
		err = fmt.Errorf("unknown command %q", cmd)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func markReady(path string) {
	if path != "" {
		_ = os.WriteFile(path, []byte("ok"), 0o644)
	}
}

func tcpServer(addr, ready string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	markReady(ready)
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		go func() { _, _ = io.Copy(io.Discard, c); c.Close() }()
	}
}

func udpServer(addr, ready string) error {
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		return err
	}
	markReady(ready)
	buf := make([]byte, 1500)
	for {
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			return err
		}
		_, _ = pc.WriteTo(buf[:n], from)
	}
}

func tcpClient(addr string) error {
	c, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return err
	}
	_, err = c.Write([]byte("ping"))
	c.Close()
	return err
}

// udpSendto uses an unconnected socket, like a resolver calling sendto.
func udpSendto(addr string) error {
	dst, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return err
	}
	pc, err := net.ListenUDP("udp", nil)
	if err != nil {
		return err
	}
	defer pc.Close()
	if _, err := pc.WriteTo([]byte("query"), dst); err != nil {
		return err
	}
	_ = pc.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1500)
	_, _, err = pc.ReadFrom(buf)
	return err
}

func hold(addr, ready string) error {
	c, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return err
	}
	defer c.Close()
	markReady(ready)
	_, err = io.Copy(io.Discard, c)
	return err
}
