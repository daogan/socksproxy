package main

import (
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"syscall"
)

const (
	socksVer5  = 0x05
	cmdConnect = 0x01

	typeIPv4   = 1
	typeDomain = 3
	typeIPv6   = 4
)

type Config struct {
	LocalAddr  string `json:"local_address"`
	ServerAddr string `json:"server_address"`
	Method     string `json:"method"`
	Password   string `json:"password"`
}

var config Config

// https://tools.ietf.org/rfc/rfc1928.txt
func handsake(conn net.Conn) error {
	var n int
	var err error
	buf := make([]byte, 258)
	// 1.
	// The client connects to the server, and sends a version
	//    identifier/method selection message:
	//
	//    +----+----------+----------+
	//    |VER | NMETHODS | METHODS  |
	//    +----+----------+----------+
	//    | 1  |    1     | 1 to 255 |
	//    +----+----------+----------+
	if n, err = io.ReadAtLeast(conn, buf, 2); err != nil {
		return err
	}
	if buf[0] != socksVer5 {
		return fmt.Errorf("expect version 5, got: %d", buf[0])
	}
	nmethods := int(buf[1])
	if n != nmethods+2 {
		return errors.New("fail to parse socks request header")
	}
	// 2.
	// The server selects from one of the methods given in METHODS, and
	//    sends a METHOD selection message:
	//
	//    +----+--------+
	//    |VER | METHOD |
	//    +----+--------+
	//    | 1  |   1    |
	//    +----+--------+
	// METHOD: X'00' NO AUTHENTICATION REQUIRED
	if _, err = conn.Write([]byte{socksVer5, 0x00}); err != nil {
		return err
	}
	return nil
}

func readRawAddr(conn net.Conn) (addr []byte, err error) {
	var n int
	buf := make([]byte, 262) // 4 + 1 + 255 + 2
	// 3.
	// The SOCKS request is formed as follows:
	//
	//    +----+-----+-------+------+----------+----------+
	//    |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
	//    +----+-----+-------+------+----------+----------+
	//    | 1  |  1  | X'00' |  1   | Variable |    2     |
	//    +----+-----+-------+------+----------+----------+
	if n, err = io.ReadAtLeast(conn, buf, 5); err != nil {
		return
	}
	if buf[0] != socksVer5 {
		err = fmt.Errorf("expect version 5, got: %d", buf[0])
		return
	}
	if buf[1] != cmdConnect {
		err = errors.New("not supported socks command")
		return
	}
	reqLen := -1
	switch buf[3] {
	case typeIPv4:
		reqLen = 4 + net.IPv4len + 2 // 4(ver+cmd+rsv+atype) + ipv4 + 2port
	case typeIPv6:
		reqLen = 4 + net.IPv6len + 2
	case typeDomain:
		reqLen = 4 + 1 + 2 + int(buf[4]) // 4(ver+cmd+rsv+atype) + 1addrLen + 2port + addrLen
	default:
		err = errors.New("not supported address type")
		return
	}

	if n != reqLen {
		err = errors.New("fail to parse socks request header")
		return
	}
	addr = buf[3:reqLen]
	return
}

func handleLocal(conn net.Conn) {
	defer conn.Close()
	if err := handsake(conn); err != nil {
		log.Println("handsake error: ", err)
		return
	}
	tgtAddr, err := readRawAddr(conn)
	if err != nil {
		log.Println("fail to get target address from connection: ", err)
		return
	}
	// 4.
	// The server evaluates the request, and
	//    returns a reply formed as follows:
	//
	//    +----+-----+-------+------+----------+----------+
	//    |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
	//    +----+-----+-------+------+----------+----------+
	//    | 1  |  1  | X'00' |  1   | Variable |    2     |
	//    +----+-----+-------+------+----------+----------+
	if _, err := conn.Write([]byte{socksVer5, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}); err != nil {
		return
	}

	remote, err := net.Dial("tcp", config.ServerAddr)
	if err != nil {
		log.Printf("fail to dail server: %v\n", err)
		return
	}
	defer remote.Close()

	l := len(tgtAddr)
	s := 1
	if tgtAddr[0] == typeDomain {
		s = 2
	}
	port := binary.BigEndian.Uint16(tgtAddr[l-2 : l])
	host := net.JoinHostPort(string(tgtAddr[s:l-2]), strconv.Itoa(int(port)))
	log.Printf("connecting %s <-> %s <-> %s\n", conn.RemoteAddr().String(), config.ServerAddr, host)

	encRemote := &Conn{Conn: remote, cipher: NewCipher(config.Method, config.Password)}
	// write {ATYP, BND.ADDR, BND.PORT} to server
	if _, err = encRemote.Write(tgtAddr); err != nil {
		log.Printf("fail to write target address: %v\n", err)
		return
	}
	go transfer(conn, encRemote)
	transfer(encRemote, conn)
}

func readTargetHost(conn *Conn) (host string, err error) {
	buf := make([]byte, 269)
	// read ATYP from client
	if _, err = io.ReadFull(conn, buf[:1]); err != nil {
		return
	}
	var reqStart, reqEnd int
	addrType := buf[0]
	switch addrType {
	case typeIPv4:
		reqStart, reqEnd = 1, 1+net.IPv4len+2 // 2 ports
	case typeIPv6:
		reqStart, reqEnd = 1, 1+net.IPv6len+2
	case typeDomain:
		if _, err = io.ReadFull(conn, buf[1:2]); err != nil {
			return
		}
		reqStart, reqEnd = 2, 2+int(buf[1])+2
	default:
		err = errors.New("not supported address type")
		return
	}
	if _, err = io.ReadFull(conn, buf[reqStart:reqEnd]); err != nil {
		return
	}

	switch addrType {
	case typeIPv4:
		host = net.IP(buf[1 : 1+net.IPv4len]).String()
	case typeIPv6:
		host = net.IP(buf[1 : 1+net.IPv6len]).String()
	case typeDomain:
		host = string(buf[2 : 2+int(buf[1])])
	}
	port := binary.BigEndian.Uint16(buf[reqEnd-2 : reqEnd])
	host = net.JoinHostPort(host, strconv.Itoa(int(port)))
	return
}

func handleServer(c net.Conn) {
	defer c.Close()
	conn := &Conn{Conn: c, cipher: NewCipher(config.Method, config.Password)}
	tgtHost, err := readTargetHost(conn)
	if err != nil {
		log.Printf("fail to get target host from connection: %v\n", err)
		return
	}
	remote, err := net.Dial("tcp", tgtHost)
	if err != nil {
		log.Printf("fail to dail host %s, err: %v\n", tgtHost, err)
		return
	}
	defer remote.Close()
	log.Printf("connecting %s <-> %s\n", c.RemoteAddr().String(), tgtHost)
	go transfer(conn, remote)
	transfer(remote, conn)
}

func run(listenAddr string, handler func(conn net.Conn)) {
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log.Fatal("listen error: ", err)
	}
	log.Printf("listening at %v ...\n", listenAddr)

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Println("accept error: ", err)
			continue
		}
		go handler(conn)
	}
}

func main() {
	flag.StringVar(&config.LocalAddr, "l", "", "local address")
	flag.StringVar(&config.ServerAddr, "s", "", "server address")
	flag.StringVar(&config.Method, "m", "aes-256-cfb", "encryption method")
	flag.StringVar(&config.Password, "p", "", "password")

	flag.Parse()

	if config.LocalAddr != "" && config.ServerAddr != "" {
		log.Println("starting local proxy")
		go run(config.LocalAddr, handleLocal)
	} else if config.ServerAddr != "" {
		log.Println("starting server proxy")
		go run(config.ServerAddr, handleServer)
	} else {
		flag.Usage()
		return
	}

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt, os.Kill, syscall.SIGINT, syscall.SIGTERM)
	sig := <-sigs
	log.Println("quit: ", sig)
}
