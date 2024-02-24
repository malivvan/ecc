package ecc

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
)

type PrivateKey [32]byte

func Private(privateKey any) (*PrivateKey, error) {
	if privateKey == nil {
		return privateKeyGenerate()
	}

	if priv, ok := privateKey.(*PrivateKey); ok {
		return priv, nil
	}

	data := getKeyData(privateKey)
	if data == nil {
		return nil, fmt.Errorf("invalid private key type: %T", privateKey)
	}

	if priv := privateKeyFromPEM(data); priv != nil {
		return priv, nil
	}
	for _, decodeFn := range privateKeyFormats {
		if priv := decodeFn(data); priv != nil {
			return priv, nil
		}
	}
	if priv := privateKeyFromString(string(data)); priv != nil {
		return priv, nil
	}
	if priv := privateKeyFromBytes(data); priv != nil {
		return priv, nil
	}
	return nil, fmt.Errorf("invalid private key data")
}

func (priv *PrivateKey) Bytes() []byte {
	return priv[:]
}

func (priv *PrivateKey) String() string {
	return Base91.Encode(priv[:])
}

func (priv *PrivateKey) PEM() []byte {
	data, err := x509.MarshalPKCS8PrivateKey(ed25519.NewKeyFromSeed(priv[:]))
	if err != nil {
		panic(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: data})
}

func (priv *PrivateKey) Sign(message []byte) ([]byte, error) {
	return Sign(priv, message)
}

func (priv *PrivateKey) Cert() ([]byte, error) {
	return Cert(priv)
}

func (priv *PrivateKey) Certify(host string) ([]byte, []byte, error) {
	return Certify(priv, host)
}

func (priv *PrivateKey) Exchange(publicKey any) ([]byte, error) {
	return Exchange(priv, publicKey)
}

func (priv *PrivateKey) ED25519() []byte {
	return ed25519.NewKeyFromSeed(priv[:])
}

func (priv *PrivateKey) X25519() []byte {
	h := sha512.New()
	h.Write(priv[:])
	out := h.Sum(nil)

	// No idea why, copy-pasted from libsodium
	out[0] &= 248
	out[31] &= 127
	out[31] |= 64

	return out[:32]
}

func (priv *PrivateKey) Equals(other *PrivateKey) bool {
	return bytes.Equal(priv[:], other[:])
}

func privateKeyGenerate() (*PrivateKey, error) {
	priv := new(PrivateKey)
	if _, err := io.ReadFull(rand.Reader, priv[:]); err != nil {
		return nil, err
	}
	return priv, nil
}

func privateKeyFromBytes(b []byte) *PrivateKey {
	if len(b) != 32 {
		return nil
	}
	priv := new(PrivateKey)
	copy(priv[:], b)
	return priv
}

func privateKeyFromString(s string) *PrivateKey {
	if len(s) != 40 {
		return nil
	}
	data, err := Base91.Decode(s)
	if err != nil {
		return nil
	}
	return privateKeyFromBytes(data)
}

func privateKeyFromPEM(privateKeyPEM []byte) *PrivateKey {
	block, _ := pem.Decode(privateKeyPEM)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil
	}
	data, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil
	}
	if priv, ok := data.(ed25519.PrivateKey); ok {
		return privateKeyFromBytes(priv.Seed())
	}
	return nil
}
