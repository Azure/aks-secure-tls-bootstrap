// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// +gocover:ignore:file These functions are only used within unit testing.
package testutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	cryptorand "crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"time"

	"software.sslmate.com/src/go-pkcs12"
)

type CertTemplate struct {
	CommonName   string
	Organization string
	IsCA         bool
	Expiration   time.Time
}

func (t CertTemplate) getX509Template() x509.Certificate {
	return x509.Certificate{
		Subject: pkix.Name{
			CommonName:   t.CommonName,
			Organization: []string{t.Organization},
		},
		IsCA:     t.IsCA,
		NotAfter: t.Expiration,
	}
}

func GenerateCertAndKeyAsEncodedPFXData(template CertTemplate) (string, error) {
	x509Template := template.getX509Template()
	x509Template.SerialNumber = big.NewInt(1)
	x509Template.NotBefore = time.Now()
	x509Template.KeyUsage = x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature
	x509Template.BasicConstraintsValid = true

	privateKey, err := rsa.GenerateKey(cryptorand.Reader, 1024)
	if err != nil {
		return "", err
	}

	certBytes, err := x509.CreateCertificate(cryptorand.Reader, &x509Template, &x509Template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return "", err
	}

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return "", err
	}

	pfxBytes, err := pkcs12.Legacy.Encode(privateKey, cert, []*x509.Certificate{}, "")
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(pfxBytes), nil
}

func GenerateCertPEM(template CertTemplate) (certPEM []byte, keyPEM []byte, err error) {
	x509Template := template.getX509Template()
	x509Template.SerialNumber = big.NewInt(1)
	x509Template.NotBefore = time.Now()
	x509Template.KeyUsage = x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature
	x509Template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	x509Template.BasicConstraintsValid = true

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), cryptorand.Reader)
	if err != nil {
		return nil, nil, err
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, &x509Template, &x509Template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, nil, err
	}
	certPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})

	keyDER, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, nil, err
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: keyDER,
	})

	return certPEM, keyPEM, nil
}

func GeneratePrivateKeyPEM() ([]byte, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), cryptorand.Reader)
	if err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: keyDER,
	})
	return keyPEM, nil
}
