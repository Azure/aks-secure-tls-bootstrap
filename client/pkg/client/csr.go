// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package client

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	cryptorand "crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
)

const (
	blockTypeCertificateRequest = "CERTIFICATE REQUEST"
)

type csrKeyBundle struct {
	csrPEM     []byte
	privateKey *ecdsa.PrivateKey
}

func makeKubeletClientCSR(hostname string) (bundle *csrKeyBundle, err error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), cryptorand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ECDSA 256 private key for kubelet client CSR: %w", err)
	}

	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			Organization: []string{"system:nodes"},
			CommonName:   fmt.Sprintf("system:node:%s", hostname),
		},
		SignatureAlgorithm: x509.ECDSAWithSHA256,
	}

	csrDER, err := x509.CreateCertificateRequest(cryptorand.Reader, template, privateKey)
	if err != nil {
		return nil, fmt.Errorf("unable to create kubelet client certificate request from template: %w", err)
	}

	pemBlock := &pem.Block{
		Type:  blockTypeCertificateRequest,
		Bytes: csrDER,
	}

	return &csrKeyBundle{
		csrPEM:     pem.EncodeToMemory(pemBlock),
		privateKey: privateKey,
	}, nil
}
