package aad

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("AAD", func() {
	Context("NewClient", func() {
		It("should construct and return a new client", func() {
			client := NewClient(logger)
			Expect(client.httpClient.RetryMax).To(Equal(maxGetTokenRetries))
			Expect(client.httpClient.RetryWaitMax).To(Equal(maxGetTokenDelay))
		})
	})
})
