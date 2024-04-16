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
	"os"
	"strings"
)

const (
	blockTypeCertificateRequest = "CERTIFICATE REQUEST"
)

// makeKubeletClientCSR returns a valid kubelet client CSR for the bootstrapping host,
// along with the associated (ECDSA) private key.
func makeKubeletClientCSR() (csrPEM []byte, privateKey *ecdsa.PrivateKey, err error) {
	hostName, err := getHostname()
	if err != nil {
		return nil, nil, fmt.Errorf("resolving hostname: %w", err)
	}

	privateKey, err = ecdsa.GenerateKey(elliptic.P256(), cryptorand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate ECDSA 256 private key for kubelet client CSR: %w", err)
	}

	template := x509.CertificateRequest{
		Subject: pkix.Name{
			Organization: []string{"system:nodes"},
			CommonName:   fmt.Sprintf("system:node:%s", hostName),
		},
		SignatureAlgorithm: x509.ECDSAWithSHA256,
	}

	csrDER, err := x509.CreateCertificateRequest(cryptorand.Reader, &template, privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to create kubelet client certificate request from template: %w", err)
	}

	pemBlock := &pem.Block{
		Type:  blockTypeCertificateRequest,
		Bytes: csrDER,
	}

	return pem.EncodeToMemory(pemBlock), privateKey, nil
}

// Returns the canonicalized (trimmed and lowercased) hostname of the VM.
func getHostname() (string, error) {
	hostName, err := os.Hostname()
	if err != nil {
		return "", fmt.Errorf("couldn't determine hostname: %w", err)
	}

	// Trim whitespaces first to avoid getting an empty hostname
	// For linux, the hostname is read from file /proc/sys/kernel/hostname directly
	hostName = strings.TrimSpace(hostName)
	if len(hostName) == 0 {
		return "", fmt.Errorf("empty hostname is invalid")
	}

	return strings.ToLower(hostName), nil
}
