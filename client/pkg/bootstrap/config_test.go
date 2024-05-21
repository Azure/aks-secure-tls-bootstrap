package bootstrap

import (
	"encoding/json"
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("config tests", func() {
	Context("Config tests", func() {
		Context("ValidateAndSet", func() {
			var cfg *Config
			defaultAzureConfigPath := "path/to/azure.json"

			BeforeEach(func() {
				cfg = &Config{
					APIServerFQDN:     "fqdn",
					CustomClientID:    "clientId",
					NextProto:         "alpn",
					AADResource:       "appID",
					ClusterCAFilePath: "path",
					KubeconfigPath:    "path",
					CertFilePath:      "path",
					KeyFilePath:       "path",
				}
			})

			When("azureConfigPath is empty", func() {
				It("should return an error", func() {
					emptyAzureConfigPath := ""
					err := cfg.ValidateAndSet(emptyAzureConfigPath)
					Expect(err).ToNot(BeNil())
					Expect(err.Error()).To(ContainSubstring("azure config path must be specified"))
				})
			})

			When("ClusterCAFilePath is empty", func() {
				It("should return an error", func() {
					cfg.ClusterCAFilePath = ""
					err := cfg.ValidateAndSet(defaultAzureConfigPath)
					Expect(err).ToNot(BeNil())
					Expect(err.Error()).To(ContainSubstring("cluster CA file path must be specified"))
				})
			})

			When("APIServerFQDN is empty", func() {
				It("should return an error", func() {
					cfg.APIServerFQDN = ""
					err := cfg.ValidateAndSet(defaultAzureConfigPath)
					Expect(err).ToNot(BeNil())
					Expect(err.Error()).To(ContainSubstring("apiserver FQDN must be specified"))
				})
			})

			When("NextProto is empty", func() {
				It("should return an error", func() {
					cfg.NextProto = ""
					err := cfg.ValidateAndSet(defaultAzureConfigPath)
					Expect(err).ToNot(BeNil())
					Expect(err.Error()).To(ContainSubstring("next proto header value must be specified"))
				})
			})

			When("AADResource is empty", func() {
				It("should return an error", func() {
					cfg.AADResource = ""
					err := cfg.ValidateAndSet(defaultAzureConfigPath)
					Expect(err).ToNot(BeNil())
					Expect(err.Error()).To(ContainSubstring("AAD resource must be specified"))
				})
			})

			When("KubeconfigPath is empty", func() {
				It("should return an error", func() {
					cfg.KubeconfigPath = ""
					err := cfg.ValidateAndSet(defaultAzureConfigPath)
					Expect(err).ToNot(BeNil())
					Expect(err.Error()).To(ContainSubstring("kubeconfig path must be specified"))
				})
			})

			When("CertFilePath is empty", func() {
				It("should return an error", func() {
					cfg.CertFilePath = ""
					err := cfg.ValidateAndSet(defaultAzureConfigPath)
					Expect(err).ToNot(BeNil())
					Expect(err.Error()).To(ContainSubstring("cert file path must be specified"))
				})
			})

			When("KeyFilePath is empty", func() {
				It("should return an error", func() {
					cfg.KeyFilePath = ""
					err := cfg.ValidateAndSet(defaultAzureConfigPath)
					Expect(err).ToNot(BeNil())
					Expect(err.Error()).To(ContainSubstring("key file path must be specified"))
				})
			})

			When("client opts are valid", func() {
				It("should validate without error", func() {
					tempDir := GinkgoT().TempDir()
					azureConfigPath := filepath.Join(tempDir, "azure.json")
					azureConfigBytes, err := json.Marshal(defaultTestCfg.AzureConfig)
					Expect(err).To(BeNil())
					err = os.WriteFile(azureConfigPath, azureConfigBytes, os.ModePerm)
					Expect(err).To(BeNil())

					err = cfg.ValidateAndSet(azureConfigPath)
					Expect(err).To(BeNil())
				})
			})
		})
	})
})
