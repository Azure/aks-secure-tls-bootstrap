package client

import (
	"fmt"

	"github.com/Azure/aks-tls-bootstrap-client/client/pkg/datamodel"
	"github.com/Azure/aks-tls-bootstrap-client/client/pkg/mocks"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"go.uber.org/mock/gomock"
)

var _ = Describe("TLS Bootstrap cloud tests", func() {
	var (
		mockCtrl        *gomock.Controller
		fileReader      *mocks.MockfileReader
		bootstrapClient *tlsBootstrapClientImpl
	)

	BeforeEach(func() {
		mockCtrl = gomock.NewController(GinkgoT())
		fileReader = mocks.NewMockfileReader(mockCtrl)
	})

	AfterEach(func() {
		mockCtrl.Finish()
	})

	Context("getAADAuthorityURL tests", func() {
		var azureConfig = &datamodel.AzureConfig{}

		When("cloud is AzurePublicCloud", func() {
			It("should return the correct AAD endpoint", func() {
				fileReader.EXPECT().ReadFile(gomock.Any()).Times(0)
				azureConfig.Cloud = azurePublicCloud

				url, err := getAADAuthorityURL(fileReader, azureConfig)
				Expect(err).To(BeNil())
				Expect(url).To(Equal("https://login.microsoftonline.com/"))
			})
		})

		When("cloud is AzureUSGovernmentCloud", func() {
			It("should return the correct AAD endpoint", func() {
				fileReader.EXPECT().ReadFile(gomock.Any()).Times(0)
				azureConfig.Cloud = azureUSGovCloud

				url, err := getAADAuthorityURL(fileReader, azureConfig)
				Expect(err).To(BeNil())
				Expect(url).To(Equal("https://login.microsoftonline.us/"))
			})
		})

		When("cloud is AzureChinaCloud", func() {
			It("should return the correct AAD endpoint", func() {
				fileReader.EXPECT().ReadFile(gomock.Any()).Times(0)
				azureConfig.Cloud = azureChinaCloud

				url, err := getAADAuthorityURL(fileReader, azureConfig)
				Expect(err).To(BeNil())
				Expect(url).To(Equal("https://login.chinacloudapi.cn/"))
			})
		})

		When("cloud is custom", func() {
			It("should return the correct AAD endpoint", func() {
				fileReader.EXPECT().ReadFile(customCloudConfigPathLinux).
					Return(
						[]byte(`{"activeDirectoryEndpoint":"https://customCloudAADEndpoint.com/"}`),
						nil,
					).
					Times(1)
				azureConfig.Cloud = "AzureStackCloud"

				url, err := getAADAuthorityURL(fileReader, azureConfig)
				Expect(err).To(BeNil())
				Expect(url).To(Equal("https://customCloudAADEndpoint.com/"))
			})
		})

		When("cloud is custom and environmnet file cannot be loaded", func() {
			It("should return an error", func() {
				fileReader.EXPECT().ReadFile(customCloudConfigPathLinux).
					Return(nil, fmt.Errorf("unable to load json file")).
					Times(1)
				azureConfig.Cloud = "AzureStackCloud"

				url, err := getAADAuthorityURL(fileReader, azureConfig)
				Expect(url).To(BeEmpty())
				Expect(err).ToNot(BeNil())
				Expect(err.Error()).To(ContainSubstring("failed to parse /etc/kubernetes/akscustom.json"))
				Expect(err.Error()).To(ContainSubstring("unable to load json file"))
			})
		})

	})

	Context("loadAzureConfig tests", func() {
		BeforeEach(func() {
			bootstrapClient = &tlsBootstrapClientImpl{
				reader: fileReader,
			}
		})

		When("on linux host", func() {
			It("should return the azure config from the default linux file path", func() {
				fileReader.EXPECT().ReadFile(azureConfigPathLinux).
					Return(
						[]byte(`{"tenantId":"tenantId","aadClientId":"clientId","aadClientSecret":"clientSecret"}`),
						nil).
					Times(1)

				err := bootstrapClient.loadAzureConfig()
				Expect(err).To(BeNil())
				Expect(bootstrapClient.azureConfig.TenantID).To(Equal("tenantId"))
				Expect(bootstrapClient.azureConfig.ClientID).To(Equal("clientId"))
				Expect(bootstrapClient.azureConfig.ClientSecret).To(Equal("clientSecret"))
			})
		})

		When("unable to load azure config from path", func() {
			It("should return an error", func() {
				fileReader.EXPECT().ReadFile(azureConfigPathLinux).
					Return(nil, fmt.Errorf("unable to load json file")).
					Times(1)

				err := bootstrapClient.loadAzureConfig()
				Expect(err).ToNot(BeNil())
				Expect(err.Error()).To(ContainSubstring("failed to parse /etc/kubernetes/azure.json"))
				Expect(err.Error()).To(ContainSubstring("unable to load json file"))
			})
		})

		When("azure config json is malformed", func() {
			It("should return an error", func() {
				fileReader.EXPECT().ReadFile(azureConfigPathLinux).
					Return([]byte(malformedJSON), nil).
					Times(1)

				err := bootstrapClient.loadAzureConfig()
				Expect(err).ToNot(BeNil())
				Expect(err.Error()).To(ContainSubstring("failed to unmarshal /etc/kubernetes/azure.json"))
			})
		})
	})
})
