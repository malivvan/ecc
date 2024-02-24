package ecc

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
)

type PublicKey [32]byte

func (priv *PrivateKey) Public() *PublicKey {
	pub := new(PublicKey)
	copy(pub[:], ed25519.NewKeyFromSeed(priv[:]).Public().(ed25519.PublicKey))
	return pub
}

func Public(publicKey any) (*PublicKey, error) {
	if publicKey == nil {
		return nil, fmt.Errorf("invalid public key data")
	}

	if pub, ok := publicKey.(*PublicKey); ok {
		return pub, nil
	}

	data := getKeyData(publicKey)
	if data == nil {
		return nil, fmt.Errorf("invalid public key type: %T", publicKey)
	}

	pub, err := publicKeyFromPEM(data)
	if err == nil {
		return pub, nil
	}
	for _, decodeFn := range publicKeyFormats {
		if pub := decodeFn(data); pub != nil {
			return pub, nil
		}
	}
	pub, err = publicKeyFromString(string(data))
	if err == nil {
		return pub, nil
	}
	pub, err = publicKeyFromBytes(data)
	if err == nil {
		return pub, nil
	}
	return nil, fmt.Errorf("invalid public key data")
}

func (pub *PublicKey) Bytes() []byte {
	b := make([]byte, 32)
	copy(b, pub[:])
	return b
}

func (pub *PublicKey) String() string {
	return Base91.Encode(pub[:])
}

func (pub *PublicKey) PEM() []byte {
	data, err := x509.MarshalPKIXPublicKey(ed25519.PublicKey(pub[:]))
	if err != nil {
		panic(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: data})
}

func (pub *PublicKey) Verify(message []byte, signature []byte) error {
	return Verify(pub, message, signature)
}

func (pub *PublicKey) Exchange(privateKey any) ([]byte, error) {
	return Exchange(privateKey, pub)
}

func (pub *PublicKey) ED25519() []byte {
	var data [32]byte
	copy(data[:], pub[:])
	return data[:]
}

func (pub *PublicKey) X25519() []byte {
	// ed25519.PublicKey is a little endian representation of the y-coordinate,
	// with the most significant bit set based on the sign of the x-coordinate.
	bigEndianY := make([]byte, 32)
	for i, b := range pub[:] {
		bigEndianY[32-i-1] = b
	}
	bigEndianY[0] &= 0b0111_1111

	// https://github.com/FiloSottile/age/blob/2194f6962c8bb3bca8a55f313d5b9302596b593b/agessh/agessh.go#L180-L209
	var curve25519P, _ = new(big.Int).SetString("57896044618658097711785492504343953926634992332820282019728792003956564819949", 10)

	// The Montgomery u-coordinate is derived through the bilinear map
	//
	//     u = (1 + y) / (1 - y)
	//
	// See https://blog.filippo.io/using-ed25519-keys-for-encryption.
	y := new(big.Int).SetBytes(bigEndianY)
	denom := big.NewInt(1)
	denom.ModInverse(denom.Sub(denom, y), curve25519P) // 1 / (1 - y)
	u := y.Mul(y.Add(y, big.NewInt(1)), denom)
	u.Mod(u, curve25519P)

	out := make([]byte, 32)
	uBytes := u.Bytes()
	for i, b := range uBytes {
		out[len(uBytes)-i-1] = b
	}

	return out
}

func (pub *PublicKey) Equals(other *PublicKey) bool {
	return bytes.Equal(pub[:], other[:])
}

func publicKeyFromString(s string) (*PublicKey, error) {
	if len(s) != 40 {
		return nil, fmt.Errorf("invalid ed25519 public data length: %d", len(s))
	}
	data, err := Base91.Decode(s)
	if err != nil {
		return nil, err
	}
	return publicKeyFromBytes(data)
}

func publicKeyFromBytes(data []byte) (*PublicKey, error) {
	if len(data) != 32 {
		return nil, fmt.Errorf("invalid ed25519 public data length: %d", len(data))
	}
	pub := new(PublicKey)
	copy(pub[:], data)
	return pub, nil
}

func publicKeyFromPEM(publicKeyPEM []byte) (*PublicKey, error) {
	block, _ := pem.Decode(publicKeyPEM)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("invalid private data toPEM data")
	}
	data, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	if pub, ok := data.(ed25519.PublicKey); ok {
		return publicKeyFromBytes(pub)
	}
	return nil, fmt.Errorf("invalid private data toPEM data")
}
