// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package bootstrap

import (
	"testing"
	"strings"
	"crypto/x509"
	"encoding/pem"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	
)



func TestMakeKubeletClientCSR(t *testing.T) {
	
	csrPEM, keyPEM, err := makeKubeletClientCSR()
	if err != nil {
		t.Errorf("%v", err)
	}

	if len(csrPEM) == 0 {
		t.Errorf("Expected non-empty CSR PEM, got empty")
	}

	if len(keyPEM) == 0 {
		t.Errorf("Expected non-empty key PEM, got empty")
	}

	block, rest := pem.Decode(csrPEM)
	if len(rest) != 0 {
		t.Errorf("Expected empty rest, got non-empty")
	}

	if block == nil {
		t.Errorf("Expected non-nil block, got nil")
	}

	csr, err := x509.ParseCertificateRequest(block.Bytes)

	if err != nil {
		t.Errorf("%v", err)
	}

	subject := csr.Subject
	if len(subject.Organization) != 1 {
		t.Errorf("Expected organization length 1, got %d", len(subject.Organization))
	}

	if subject.Organization[0] != "system:nodes" {
		t.Errorf("Expected organization 'system:nodes', got '%s'", subject.Organization[0])
	}

	if !strings.HasPrefix(subject.CommonName, "system:node:") {
		t.Errorf("Expected common name to start with 'system:node:', got '%s'", subject.CommonName)
	}

	if csr.SignatureAlgorithm != x509.ECDSAWithSHA256 {
		t.Errorf("Expected ECDSAWithSHA256, got %v", csr.SignatureAlgorithm)
	}

	block, rest = pem.Decode(keyPEM)
	if len(rest) != 0 {
		t.Errorf("Expected empty rest, got non-empty %d", len(rest))
	}

	if block == nil {
		t.Errorf("Expected non-nil block, got nil")
	}

	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		t.Errorf("%v", err)
	}

	if key == nil {
		t.Errorf("Expected non-nil key, got nil")
	}

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
