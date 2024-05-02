package crypt

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

func GenerateKeyPair(bitSize int) ([]byte, []byte, error) {
	if bitSize == 0 {
		bitSize = 4096
	}

	if bitSize < 2048 {
		return nil, nil, fmt.Errorf("key to weak. size must be greater than 2048")
	}

	if bitSize > 16384 {
		return nil, nil, fmt.Errorf("key to large. size must be less than 16384")
	}

	key, err := rsa.GenerateKey(rand.Reader, bitSize)

	if err != nil {
		return nil, nil, err
	}

	keyPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(key),
		},
	)

	pub := key.Public()

	pubPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: x509.MarshalPKCS1PublicKey(pub.(*rsa.PublicKey)),
		},
	)

	return keyPEM, pubPEM, nil
}
