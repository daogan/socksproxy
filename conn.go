package main

import (
	"crypto/aes"
	"io"
	"net"
	"time"
)

var timeout = 120 * time.Second

type Conn struct {
	net.Conn
	cipher *Cipher
}

func NewConn(conn net.Conn, cipher *Cipher) *Conn {
	return &Conn{Conn: conn, cipher: cipher}
}

func (c *Conn) Close() error {
	return c.Conn.Close()
}

func (c *Conn) Read(b []byte) (n int, err error) {
	if c.cipher.dec == nil {
		iv := make([]byte, aes.BlockSize)
		if _, err = io.ReadFull(c.Conn, iv); err != nil {
			return
		}
		if err = c.cipher.initDecrypt(iv); err != nil {
			return
		}
	}
	buf := bytePool.GetAtLeast(len(b))
	defer bytePool.Put(buf)
	encBytes := buf[:len(b)]
	n, err = c.Conn.Read(encBytes)
	if n > 0 {
		c.cipher.decrypt(b[:n], encBytes[:n])
	}
	return
}

func (c *Conn) Write(b []byte) (n int, err error) {
	var iv []byte
	if c.cipher.enc == nil {
		iv, err = c.cipher.initEncrypt()
		if err != nil {
			return
		}
	}
	encLen := len(iv) + len(b)
	buf := bytePool.GetAtLeast(encLen)
	defer bytePool.Put(buf)
	encBytes := buf[:encLen]
	if len(iv) > 0 {
		copy(encBytes, iv)
	}
	c.cipher.encrypt(encBytes[len(iv):], b)
	n, err = c.Conn.Write(encBytes)
	return
}

func transfer(dst, src net.Conn) {
	buf := bytePool.Get()
	defer bytePool.Put(buf)
	for {
		src.SetReadDeadline(time.Now().Add(timeout))
		n, err := src.Read(buf)
		if n > 0 {
			if _, err := dst.Write(buf[0:n]); err != nil {
				break
			}
		}
		if err != nil {
			break
		}
	}
	return
}
