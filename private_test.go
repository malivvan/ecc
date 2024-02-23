package ecc

import (
	"bytes"
	"testing"
)

func TestPrivateKey(t *testing.T) {
	initDeterministic()

	priv, err := Private(nil)
	if err != nil {
		t.Fatal(err)
	}
	if priv == nil {
		t.Fatal("nil private key")
	}
	if !bytes.Equal(priv[:], []byte{
		0x60, 0x5b, 0x33, 0x13, 0x78, 0x52, 0x34, 0xfd, 0x29, 0x41, 0xee, 0xa6, 0xed, 0x3e, 0xe2, 0x15,
		0xef, 0x98, 0x3a, 0xf8, 0x9f, 0x1b, 0xe3, 0x81, 0xdc, 0x12, 0x37, 0xfb, 0xaa, 0x1d, 0x06, 0x2e,
	}) {
		t.Fatal("invalid private key bytes")
	}
	if priv.String() != "B=C.o_cYw~5B'=z^cGo*wRbuM/ix%y5Gz<wlbEBB" {
		t.Fatal("invalid private key string")
	}
	if string(priv.PEM()) != `-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIGBbMxN4UjT9KUHupu0+4hXvmDr4nxvjgdwSN/uqHQYu
-----END PRIVATE KEY-----
` {
		t.Fatal("invalid private key pem")
	}

	privFromBytes, err := Private(priv.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(priv[:], privFromBytes[:]) {
		t.Fatal("invalid private key from bytes")
	}

	privFromString, err := Private(priv.String())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(priv[:], privFromString[:]) {
		t.Fatal("invalid private key from string")
	}

	privFromPEM, err := Private(priv.PEM())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(priv[:], privFromPEM[:]) {
		t.Fatal("invalid private key from pem")
	}
}
