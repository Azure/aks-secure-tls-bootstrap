package client

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("SecureTLSBootstrapClientOpts tests", func() {
	Context("Validate test", func() {
		var opts SecureTLSBootstrapClientOpts

		BeforeEach(func() {
			opts = SecureTLSBootstrapClientOpts{
				CustomClientID: "clientId",
				NextProto:      "alpn",
				AADResource:    "appID",
				LogFormat:      "json",
			}
		})

		When("NextProto is empty", func() {
			It("should return an error", func() {
				opts.NextProto = ""
				err := opts.Validate()
				Expect(err).ToNot(BeNil())
				Expect(err.Error()).To(ContainSubstring("next-proto must be specified to generate bootstrap tokens"))
			})
		})

		When("AADResource is empty", func() {
			It("should return an error", func() {
				opts.AADResource = ""
				err := opts.Validate()
				Expect(err).ToNot(BeNil())
				Expect(err.Error()).To(ContainSubstring("aad-resource must be specified to generate bootstrap tokens"))
			})
		})

		When("client opts are valid", func() {
			It("should validagte without error", func() {
				err := opts.Validate()
				Expect(err).To(BeNil())
			})
		})
	})
})
