package ecc

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"time"
)

var (
	Organization = "ECC"

	CertValidity = func() (time.Time, time.Time) {
		now := time.Now().In(time.UTC)
		notBefore := time.Date(now.Year()-(now.Year()%10), time.January, 1, 0, 0, 0, 0, time.UTC)
		notAfter := time.Date(now.Year()-(now.Year()%10)+9, time.December, 31, 23, 59, 59, 0, time.UTC)
		return notBefore, notAfter
	}

	CertifyValidity = func() (time.Time, time.Time) {
		now := time.Now().In(time.UTC)
		notBefore := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
		notAfter := time.Date(now.Year(), now.Month(), now.Day(), 23, 59, 59, 0, time.UTC)
		return notBefore, notAfter
	}
)

var (
	privateKeyFormats []func([]byte) *PrivateKey
	publicKeyFormats  []func([]byte) *PublicKey
)

func Register(fn any) {
	switch v := fn.(type) {
	case func([]byte) *PrivateKey:
		privateKeyFormats = append(privateKeyFormats, v)
	case func([]byte) *PublicKey:
		publicKeyFormats = append(publicKeyFormats, v)
	default:
		panic(fmt.Errorf("invalid register type: %T", fn))
	}
}

func Sign(privateKey any, message []byte) ([]byte, error) {
	priv, err := Private(privateKey)
	if err != nil {
		return nil, err
	}
	return ed25519.Sign(ed25519.NewKeyFromSeed(priv[:]), message), nil
}

func Verify(publicKey any, message, signature []byte) error {
	pub, err := Public(publicKey)
	if err != nil {
		return err
	}
	if !ed25519.Verify(pub[:], message, signature) {
		return fmt.Errorf("invalid signature")
	}
	return nil
}

func Exchange(privateKey, publicKey any) ([]byte, error) {
	priv, err := Private(privateKey)
	if err != nil {
		return nil, err
	}
	pub, err := Public(publicKey)
	if err != nil {
		return nil, err
	}
	ecdhPriv, err := ecdh.X25519().NewPrivateKey(priv.X25519())
	if err != nil {
		return nil, err
	}
	ecdhPub, err := ecdh.X25519().NewPublicKey(pub.X25519())
	if err != nil {
		return nil, err
	}
	secret, err := ecdhPriv.ECDH(ecdhPub)
	if err != nil {
		return nil, err
	}
	return secret, nil
}

func Cert(privateKey any) ([]byte, error) {

	caPriv, err := Private(privateKey)
	if err != nil {
		return nil, err
	}
	caSerialHasher := md5.New()
	caSerialHasher.Write(caPriv.Public()[:])
	caSerial := big.NewInt(0).SetBytes(caSerialHasher.Sum(nil))
	caSubject := pkix.Name{
		CommonName:   Organization + " CA",
		Organization: []string{Organization},
		SerialNumber: caSerial.String(),
	}
	ca := &x509.Certificate{
		SerialNumber:          caSerial,
		Subject:               caSubject,
		Issuer:                caSubject,
		SignatureAlgorithm:    x509.PureEd25519,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	ca.NotBefore, ca.NotAfter = CertValidity()
	caKey := ed25519.NewKeyFromSeed(caPriv[:])
	caData, err := x509.CreateCertificate(nil, ca, ca, caKey.Public(), caKey)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caData,
	}), nil
}

func Certify(privateKey any, host string) ([]byte, []byte, error) {

	caPriv, err := Private(privateKey)
	if err != nil {
		return nil, nil, err
	}
	caKey := ed25519.NewKeyFromSeed(caPriv[:])
	caBlock, err := Cert(privateKey)
	if err != nil {
		return nil, nil, err
	}
	block, _ := pem.Decode(caBlock)
	if block.Type != "CERTIFICATE" {
		return nil, nil, fmt.Errorf("invalid certificate pem type")
	}
	ca, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, err
	}

	certKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	certSerialHasher := md5.New()
	certSerialHasher.Write(x509.MarshalPKCS1PublicKey(certKey.Public().(*rsa.PublicKey)))
	certSerial := big.NewInt(0).SetBytes(certSerialHasher.Sum(nil))
	cert := &x509.Certificate{
		SerialNumber: certSerial,
		Subject: pkix.Name{
			CommonName:   host,
			Organization: []string{Organization},
			SerialNumber: certSerial.String(),
		},
		Issuer:                ca.Subject,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	cert.NotBefore, cert.NotAfter = CertifyValidity()
	if ip := net.ParseIP(host); ip != nil {
		cert.IPAddresses = append(cert.IPAddresses, ip)
	} else {
		cert.DNSNames = append(cert.DNSNames, host)
	}
	certData, err := x509.CreateCertificate(rand.Reader, cert, ca, certKey.Public(), caKey)
	if err != nil {
		return nil, nil, err
	}

	return pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: certData,
		}),
		pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(certKey),
		}), nil
}

func getKeyData(key any) (b []byte) {
	switch v := key.(type) {
	case io.Reader:
		b = make([]byte, 128)
		n, err := v.Read(b)
		if err != nil {
			return nil
		}
		b = b[:n]
		if f, ok := v.(*os.File); ok {
			_ = f.Close()
		}
	case []byte:
		b = v
	case string:
		b = []byte(v)
	}
	return
}
