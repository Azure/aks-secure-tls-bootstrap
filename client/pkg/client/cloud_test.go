// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package client

import (
	"fmt"

	utilmocks "github.com/Azure/aks-secure-tls-bootstrap/client/pkg/util/mocks"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"go.uber.org/mock/gomock"
)

var _ = Describe("TLS Bootstrap cloud tests", func() {
	Context("loadAzureConfig tests", func() {
		var (
			mockCtrl *gomock.Controller
			fs       *utilmocks.MockFS
		)

		BeforeEach(func() {
			mockCtrl = gomock.NewController(GinkgoT())
			fs = utilmocks.NewMockFS(mockCtrl)
		})

		AfterEach(func() {
			mockCtrl.Finish()
		})

		When("on linux host", func() {
			It("should return the azure config from the default linux file path", func() {
				fs.EXPECT().ReadFile(azureConfigPathLinux).
					Return(
						[]byte(`{"tenantId":"tenantId","aadClientId":"clientId","aadClientSecret":"clientSecret"}`),
						nil).
					Times(1)

				azureConfig, err := loadAzureConfig(fs)
				Expect(err).To(BeNil())
				Expect(azureConfig.TenantID).To(Equal("tenantId"))
				Expect(azureConfig.ClientID).To(Equal("clientId"))
				Expect(azureConfig.ClientSecret).To(Equal("clientSecret"))
			})
		})

		When("unable to load azure config from path", func() {
			It("should return an error", func() {
				fs.EXPECT().ReadFile(azureConfigPathLinux).
					Return(nil, fmt.Errorf("unable to load json file")).
					Times(1)

				azureConfig, err := loadAzureConfig(fs)
				Expect(azureConfig).To(BeNil())
				Expect(err).ToNot(BeNil())
				Expect(err.Error()).To(ContainSubstring("failed to parse /etc/kubernetes/azure.json"))
				Expect(err.Error()).To(ContainSubstring("unable to load json file"))
			})
		})

		When("azure config json is malformed", func() {
			It("should return an error", func() {
				fs.EXPECT().ReadFile(azureConfigPathLinux).
					Return([]byte(`{{}`), nil).
					Times(1)

				azureConfig, err := loadAzureConfig(fs)
				Expect(azureConfig).To(BeNil())
				Expect(err).ToNot(BeNil())
				Expect(err.Error()).To(ContainSubstring("failed to unmarshal /etc/kubernetes/azure.json"))
			})
		})
	})
})
