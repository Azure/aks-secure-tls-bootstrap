// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package bootstrap

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	cryptorand "crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"os"
	"strings"

	"github.com/Azure/aks-secure-tls-bootstrap/client/internal/log"
	"go.uber.org/zap"
)

// makeKubeletClientCSR returns a valid kubelet client CSR for the bootstrapping host, along with the associated (ECDSA) private key.
func makeKubeletClientCSR(ctx context.Context) (csrPEM, keyPEM []byte, err error) {
	logger := log.MustGetLogger(ctx)

	hostname, err := getHostname()
	if err != nil {
		return nil, nil, fmt.Errorf("resolving hostname: %w", err)
	}
	logger.Info("resolved hostname", zap.String("hostname", hostname))

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), cryptorand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate ECDSA 256 private key for kubelet client CSR: %w", err)
	}

	template := x509.CertificateRequest{
		Subject: pkix.Name{
			Organization: []string{"system:nodes"},
			CommonName:   fmt.Sprintf("system:node:%s", hostname),
		},
		SignatureAlgorithm: x509.ECDSAWithSHA256,
	}
	logger.Info("generated CSR subject common name", zap.String("subjectCommonName", template.Subject.CommonName))

	csrDER, err := x509.CreateCertificateRequest(cryptorand.Reader, &template, privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to create kubelet client certificate request from template: %w", err)
	}
	csrBlock := &pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrDER,
	}

	keyDER, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to marshal new EC private key: %w", err)
	}
	keyBlock := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: keyDER,
	}

	return pem.EncodeToMemory(csrBlock), pem.EncodeToMemory(keyBlock), nil
}

// Returns the canonicalized (trimmed and lowercased) hostname of the VM.
func getHostname() (string, error) {
	hostname, err := os.Hostname()
	if err != nil {
		return "", fmt.Errorf("resolving hostname: %w", err)
	}

	// Trim whitespaces first to avoid getting an empty hostname
	// For linux, the hostname is read from file /proc/sys/kernel/hostname directly
	hostname = strings.TrimSpace(hostname)
	if len(hostname) == 0 {
		return "", fmt.Errorf("empty hostname is invalid")
	}

	return strings.ToLower(hostname), nil
}
