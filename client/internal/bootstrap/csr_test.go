// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.
package bootstrap

import (
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMakeKubeletClientCSR(t *testing.T) {
	csrPEM, keyPEM, err := makeKubeletClientCSR()
	assert.NoError(t, err)
	assert.NotEmpty(t, keyPEM)
	assert.NotEmpty(t, csrPEM)

	block, rest := pem.Decode(csrPEM)
	assert.Empty(t, rest)
	assert.NotNil(t, block)

	csr, err := x509.ParseCertificateRequest(block.Bytes)
	assert.NoError(t, err)

	subject := csr.Subject
	assert.Len(t, subject.Organization, 1)
	assert.Equal(t, "system:nodes", subject.Organization[0])
	assert.True(t, strings.HasPrefix(subject.CommonName, "system:node:"))
	assert.Equal(t, x509.ECDSAWithSHA256, csr.SignatureAlgorithm)

	block, rest = pem.Decode(keyPEM)
	assert.Empty(t, rest)
	assert.NotNil(t, block)

	key, err := x509.ParseECPrivateKey(block.Bytes)
	assert.NoError(t, err)
	assert.NotNil(t, key)
}
