// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package aad

import (
	"fmt"

	"github.com/Azure/aks-secure-tls-bootstrap/client/pkg/datamodel"
	utilmocks "github.com/Azure/aks-secure-tls-bootstrap/client/pkg/util/mocks"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"go.uber.org/mock/gomock"
)

var _ = Describe("TLS Bootstrap cloud tests", func() {
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

	Context("getAADAuthorityURL tests", func() {
		var azureConfig = &datamodel.AzureConfig{}

		When("cloud is AzurePublicCloud", func() {
			It("should return the correct AAD endpoint", func() {
				fs.EXPECT().ReadFile(gomock.Any()).Times(0)
				azureConfig.Cloud = azurePublicCloud

				url, err := getAADAuthorityURL(fs, azureConfig)
				Expect(err).To(BeNil())
				Expect(url).To(Equal("https://login.microsoftonline.com/"))
			})
		})

		When("cloud is AzureUSGovernmentCloud", func() {
			It("should return the correct AAD endpoint", func() {
				fs.EXPECT().ReadFile(gomock.Any()).Times(0)
				azureConfig.Cloud = azureUSGovCloud

				url, err := getAADAuthorityURL(fs, azureConfig)
				Expect(err).To(BeNil())
				Expect(url).To(Equal("https://login.microsoftonline.us/"))
			})
		})

		When("cloud is AzureChinaCloud", func() {
			It("should return the correct AAD endpoint", func() {
				fs.EXPECT().ReadFile(gomock.Any()).Times(0)
				azureConfig.Cloud = azureChinaCloud

				url, err := getAADAuthorityURL(fs, azureConfig)
				Expect(err).To(BeNil())
				Expect(url).To(Equal("https://login.chinacloudapi.cn/"))
			})
		})

		When("cloud is custom", func() {
			It("should return the correct AAD endpoint", func() {
				fs.EXPECT().ReadFile(customCloudConfigPathLinux).
					Return(
						[]byte(`{"activeDirectoryEndpoint":"https://customCloudAADEndpoint.com/"}`),
						nil,
					).
					Times(1)
				azureConfig.Cloud = "AzureStackCloud"

				url, err := getAADAuthorityURL(fs, azureConfig)
				Expect(err).To(BeNil())
				Expect(url).To(Equal("https://customCloudAADEndpoint.com/"))
			})
		})

		When("cloud is custom and environmnet file cannot be loaded", func() {
			It("should return an error", func() {
				fs.EXPECT().ReadFile(customCloudConfigPathLinux).
					Return(nil, fmt.Errorf("unable to load json file")).
					Times(1)
				azureConfig.Cloud = "AzureStackCloud"

				url, err := getAADAuthorityURL(fs, azureConfig)
				Expect(url).To(BeEmpty())
				Expect(err).ToNot(BeNil())
				Expect(err.Error()).To(ContainSubstring("failed to parse /etc/kubernetes/akscustom.json"))
				Expect(err.Error()).To(ContainSubstring("unable to load json file"))
			})
		})

	})
})
