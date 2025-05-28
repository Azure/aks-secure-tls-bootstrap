// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package bootstrap

import (
	"testing"
	"strings"
	"crypto/x509"
	"encoding/pem"
	"github.com/stretchr/testify/assert"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	
)



func TestMakeKubeletClientCSR(t *testing.T) {
	
	csrPEM, keyPEM, err := makeKubeletClientCSR()
	assert.NoError(t,err)
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

var _ = Describe("CSR tests", func() {
	Context("makeKubeletClientCSR tests", func() {
		It("should generate and return a new kubelet client CSR for the provided hostname", func() {
			csrPEM, keyPEM, err := makeKubeletClientCSR()
			Expect(err).To(BeNil())
			Expect(csrPEM).ToNot(BeEmpty())
			Expect(keyPEM).ToNot(BeEmpty())

			block, rest := pem.Decode(csrPEM)
			Expect(rest).To(BeEmpty())
			Expect(block).ToNot(BeNil())

			csr, err := x509.ParseCertificateRequest(block.Bytes)
			Expect(err).To(BeNil())

			subject := csr.Subject
			Expect(len(subject.Organization)).To(Equal(1))
			Expect(subject.Organization[0]).To(Equal("system:nodes"))
			Expect(subject.CommonName).To(HavePrefix("system:node:"))
			Expect(csr.SignatureAlgorithm).To(Equal(x509.ECDSAWithSHA256))

			block, rest = pem.Decode(keyPEM)
			Expect(rest).To(BeEmpty())
			Expect(block).ToNot(BeNil())

			key, err := x509.ParseECPrivateKey(block.Bytes)
			Expect(err).To(BeNil())
			Expect(key).ToNot(BeNil())
		})
	})
})
