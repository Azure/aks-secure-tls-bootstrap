package aad

import (
	"github.com/Azure/aks-secure-tls-bootstrap/client/pkg/util"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("AAD", func() {
	Context("NewClient", func() {
		It("should construct and return a new client", func() {
			client := NewClient(util.NewOSFS(), logger)
			Expect(client.httpClient.RetryMax).To(Equal(maxGetTokenRetries))
			Expect(client.httpClient.RetryWaitMax).To(Equal(maxGetTokenDelay))
		})
	})
})
