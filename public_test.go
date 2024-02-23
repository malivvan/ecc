package ecc

import (
	"bytes"
	"testing"
)

func TestPublicKey(t *testing.T) {
	initDeterministic()

	priv, err := Private(nil)
	if err != nil {
		t.Fatal(err)
	}
	if priv == nil {
		t.Fatal("nil private key")
	}

	pub := priv.Public()
	if pub == nil {
		t.Fatal("nil public key")
	}

	if !bytes.Equal(pub[:], []byte{
		0xf0, 0x6f, 0xea, 0xe1, 0x5c, 0x51, 0x5c, 0xbb, 0xb8, 0x4b, 0x0e, 0x23, 0x32, 0x02, 0xd9, 0x17,
		0xac, 0xe2, 0x3e, 0x4c, 0xb9, 0xee, 0x3c, 0x9d, 0x5d, 0xb5, 0x4f, 0x8b, 0x9f, 0xcc, 0xb5, 0x75,
	}) {
		t.Fatal("invalid public key bytes")
	}
	if pub.String() != "<sKrd%b*-gsQji5Rg+ICk*[)0g$-P#+#:fCO<l1C" {
		t.Fatal("invalid public key string")
	}
	if string(pub.PEM()) != `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA8G/q4VxRXLu4Sw4jMgLZF6ziPky57jydXbVPi5/MtXU=
-----END PUBLIC KEY-----
` {
		t.Fatal("invalid public key pem")
	}

	pubFromBytes, err := Public(pub.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pub[:], pubFromBytes[:]) {
		t.Fatal("invalid public key from bytes")
	}

	pubFromString, err := Public(pub.String())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pub[:], pubFromString[:]) {
		t.Fatal("invalid public key from string")
	}

	pubFromPEM, err := Public(pub.PEM())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pub[:], pubFromPEM[:]) {
		t.Fatal("invalid public key from pem")
	}
}
