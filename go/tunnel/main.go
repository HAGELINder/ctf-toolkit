package main

// tunnel — Go rewrite of tunnel.py
// TCP port forwarder / pivot relay / SOCKS5 proxy. Pure stdlib.
//
// Build (Linux):
//   go build -ldflags "-s -w" -trimpath -o tunnel .
//
// Build (Windows, cross-compile):
//   GOOS=windows GOARCH=amd64 go build -ldflags "-s -w" -trimpath -o nethelper.exe .
//
// Usage:
//   ./tunnel forward 8080 10.10.0.5 80        # forward localhost:8080 → 10.10.0.5:80
//   ./tunnel forward 8080 10.10.0.5 80 -v     # verbose
//   ./tunnel bind 4444                         # pipe two inbound connections
//   ./tunnel socks5 1080                       # SOCKS5 proxy on 1080
//   ./tunnel socks5                            # default port 1080

import (
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"sync"
	"time"
)

var verbose bool

func logf(format string, a ...any) {
	if verbose {
		fmt.Printf("[%s] "+format+"\n", append([]any{time.Now().Format("15:04:05")}, a...)...)
	}
}

func infof(format string, a ...any) {
	fmt.Printf("[*] "+format+"\n", a...)
}

func okf(format string, a ...any) {
	fmt.Printf("[+] "+format+"\n", a...)
}

func errf(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "[!] "+format+"\n", a...)
}

// ── Core relay ─────────────────────────────────────────────────────────────────

func relay(a, b net.Conn, tag string) {
	defer a.Close()
	defer b.Close()

	var wg sync.WaitGroup
	pipe := func(dst, src net.Conn, dir string) {
		defer wg.Done()
		n, _ := io.Copy(dst, src)
		logf("%s %s closed (%d bytes)", tag, dir, n)
		dst.Close()
		src.Close()
	}

	wg.Add(2)
	go pipe(a, b, "←")
	go pipe(b, a, "→")
	wg.Wait()
}

func listen(host string, port int) (net.Listener, error) {
	return net.Listen("tcp", fmt.Sprintf("%s:%d", host, port))
}

// ── MODE 1: Forward ────────────────────────────────────────────────────────────

func modeForward(host string, lport int, dstHost string, dstPort int) {
	ln, err := listen(host, lport)
	if err != nil {
		errf("Cannot listen on %s:%d — %v", host, lport, err)
		os.Exit(1)
	}
	infof("Forwarding  %s:%d  →  %s:%d  (Ctrl-C to stop)", host, lport, dstHost, dstPort)

	id := 0
	for {
		conn, err := ln.Accept()
		if err != nil {
			continue
		}
		id++
		tag := fmt.Sprintf("[%d] %s", id, conn.RemoteAddr())
		logf("Accepted %s", tag)

		go func(c net.Conn, t string) {
			upstream, err := net.DialTimeout("tcp",
				fmt.Sprintf("%s:%d", dstHost, dstPort), 10*time.Second)
			if err != nil {
				errf("%s → cannot connect to %s:%d: %v", t, dstHost, dstPort, err)
				c.Close()
				return
			}
			okf("%s → %s:%d", t, dstHost, dstPort)
			relay(c, upstream, t)
		}(conn, tag)
	}
}

// ── MODE 2: Bind relay ─────────────────────────────────────────────────────────

func modeBind(host string, port int) {
	ln, err := listen(host, port)
	if err != nil {
		errf("Cannot listen on %s:%d — %v", host, port, err)
		os.Exit(1)
	}
	infof("Bind relay on %s:%d — waiting for 2 connections …", host, port)

	pair := 0
	for {
		c1, err := ln.Accept()
		if err != nil {
			continue
		}
		okf("First  connection from %s — waiting for second …", c1.RemoteAddr())

		c2, err := ln.Accept()
		if err != nil {
			c1.Close()
			continue
		}
		okf("Second connection from %s — relaying", c2.RemoteAddr())

		pair++
		go relay(c1, c2, fmt.Sprintf("[pair-%d]", pair))
	}
}

// ── MODE 3: SOCKS5 proxy ───────────────────────────────────────────────────────

const (
	socks5Ver      = 0x05
	socks5AuthNone = 0x00
	socks5CmdConn  = 0x01
	socks5AtypIPv4 = 0x01
	socks5AtypDom  = 0x03
	socks5AtypIPv6 = 0x04
)

func modeSocks5(host string, port int) {
	ln, err := listen(host, port)
	if err != nil {
		errf("Cannot listen on %s:%d — %v", host, port, err)
		os.Exit(1)
	}
	infof("SOCKS5 proxy on %s:%d", host, port)
	infof("proxychains: socks5 127.0.0.1 %d", port)
	infof("curl:        curl --socks5 127.0.0.1:%d http://target/", port)

	id := 0
	for {
		conn, err := ln.Accept()
		if err != nil {
			continue
		}
		id++
		go handleSocks5(conn, id)
	}
}

func readExact(c net.Conn, n int) ([]byte, error) {
	buf := make([]byte, n)
	_, err := io.ReadFull(c, buf)
	return buf, err
}

func handleSocks5(c net.Conn, id int) {
	defer func() {
		if r := recover(); r != nil {
			c.Close()
		}
	}()

	tag := fmt.Sprintf("[s5-%d %s]", id, c.RemoteAddr())

	// Greeting
	hdr, err := readExact(c, 2)
	if err != nil || hdr[0] != socks5Ver {
		c.Close()
		return
	}
	nMethods := int(hdr[1])
	if _, err := readExact(c, nMethods); err != nil {
		c.Close()
		return
	}
	c.Write([]byte{socks5Ver, socks5AuthNone})

	// Request
	req, err := readExact(c, 4)
	if err != nil || req[0] != socks5Ver || req[1] != socks5CmdConn {
		c.Write([]byte{socks5Ver, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		c.Close()
		return
	}

	var dstHost string
	switch req[3] {
	case socks5AtypIPv4:
		raw, err := readExact(c, 4)
		if err != nil {
			c.Close()
			return
		}
		dstHost = net.IP(raw).String()
	case socks5AtypDom:
		ln, err := readExact(c, 1)
		if err != nil {
			c.Close()
			return
		}
		dom, err := readExact(c, int(ln[0]))
		if err != nil {
			c.Close()
			return
		}
		dstHost = string(dom)
	case socks5AtypIPv6:
		raw, err := readExact(c, 16)
		if err != nil {
			c.Close()
			return
		}
		dstHost = net.IP(raw).String()
	default:
		c.Write([]byte{socks5Ver, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		c.Close()
		return
	}

	portRaw, err := readExact(c, 2)
	if err != nil {
		c.Close()
		return
	}
	dstPort := binary.BigEndian.Uint16(portRaw)
	addr := fmt.Sprintf("%s:%d", dstHost, dstPort)

	upstream, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		logf("%s cannot connect to %s: %v", tag, addr, err)
		c.Write([]byte{socks5Ver, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		c.Close()
		return
	}

	// Success reply
	localAddr := upstream.LocalAddr().(*net.TCPAddr)
	ip := localAddr.IP.To4()
	if ip == nil {
		ip = []byte{0, 0, 0, 0}
	}
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, uint16(localAddr.Port))
	reply := append([]byte{socks5Ver, 0x00, 0x00, socks5AtypIPv4}, ip...)
	reply = append(reply, portBytes...)
	c.Write(reply)

	okf("%s → %s", tag, addr)
	relay(c, upstream, tag)
}

// ── Entry point ────────────────────────────────────────────────────────────────

func usage() {
	fmt.Print(`Usage:
  tunnel forward <lport> <dst-host> <dst-port> [--host bind-addr] [-v]
  tunnel bind    <port>                         [--host bind-addr] [-v]
  tunnel socks5  [port]                         [--host bind-addr] [-v]

Flags:
  --host  bind address (default 0.0.0.0)
  -v      verbose logging

Examples:
  tunnel forward 8080 10.10.0.5 80
  tunnel bind 4444
  tunnel socks5 1080
`)
	os.Exit(1)
}

func main() {
	if len(os.Args) < 2 {
		usage()
	}

	mode := os.Args[1]
	args := os.Args[2:]

	fs := flag.NewFlagSet("tunnel", flag.ExitOnError)
	bindHost := fs.String("host", "0.0.0.0", "bind address")
	fs.BoolVar(&verbose, "v", false, "verbose")
	fs.BoolVar(&verbose, "verbose", false, "verbose")

	switch mode {
	case "forward":
		if len(args) < 3 {
			errf("forward requires: <lport> <dst-host> <dst-port>")
			usage()
		}
		fs.Parse(args[3:])
		lport, _ := strconv.Atoi(args[0])
		dstPort, _ := strconv.Atoi(args[2])
		modeForward(*bindHost, lport, args[1], dstPort)

	case "bind":
		if len(args) < 1 {
			errf("bind requires: <port>")
			usage()
		}
		fs.Parse(args[1:])
		port, _ := strconv.Atoi(args[0])
		modeBind(*bindHost, port)

	case "socks5":
		port := 1080
		if len(args) > 0 && args[0][0] != '-' {
			port, _ = strconv.Atoi(args[0])
			fs.Parse(args[1:])
		} else {
			fs.Parse(args)
		}
		modeSocks5(*bindHost, port)

	default:
		errf("unknown mode: %s", mode)
		usage()
	}
}
