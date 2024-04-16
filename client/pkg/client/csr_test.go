// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package client

import (
	"crypto/elliptic"
	"crypto/x509"
	"encoding/pem"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("CSR tests", func() {
	Context("makeKubeletClientCSR tests", func() {
		It("should generate and return a new kubelet client CSR for the provided hostname", func() {
			csrPEM, privateKey, err := makeKubeletClientCSR()
			Expect(err).To(BeNil())
			Expect(csrPEM).ToNot(BeEmpty())
			Expect(privateKey.Curve).To(Equal(elliptic.P256()))

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
		})
	})
})
