package main

import (
	"fmt"
	"io"

	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
)

type Cipher struct {
	enc cipher.Stream
	dec cipher.Stream
	key []byte
}

var keyLenMap = map[string]int{
	"aes-128-cfb": 16,
	"aes-192-cfb": 24,
	"aes-256-cfb": 32,
}

func toKey(method, password string) []byte {
	var keyLen int
	if l, ok := keyLenMap[method]; ok {
		keyLen = l
	} else {
		keyLen = 32
	}
	bs := sha256.Sum256([]byte(password))
	return bs[:keyLen]
}

func NewCipher(method, password string) *Cipher {
	key := toKey(method, password)
	return &Cipher{key: key}
}

func (c *Cipher) initEncrypt() (iv []byte, err error) {
	block, err := aes.NewCipher(c.key)
	if err != nil {
		return
	}
	iv = make([]byte, aes.BlockSize)
	if _, err = io.ReadFull(rand.Reader, iv); err != nil {
		return nil, fmt.Errorf("Can't build random iv: %v", err)
	}
	c.enc = cipher.NewCFBEncrypter(block, iv)
	return
}

func (c *Cipher) initDecrypt(iv []byte) error {
	block, err := aes.NewCipher(c.key)
	if err != nil {
		return err
	}
	if len(iv) != aes.BlockSize {
		return fmt.Errorf("Invalid IV length: %d", len(iv))
	}
	c.dec = cipher.NewCFBDecrypter(block, iv)
	return nil
}

func (c *Cipher) decrypt(dst, src []byte) {
	c.dec.XORKeyStream(dst, src)
}

func (c *Cipher) encrypt(dst, src []byte) {
	c.enc.XORKeyStream(dst, src)
}
