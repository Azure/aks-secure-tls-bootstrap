// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package bootstrap

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	"github.com/Azure/aks-secure-tls-bootstrap/client/internal/datamodel"
	"github.com/Azure/go-autorest/autorest/azure"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("config tests", func() {
	Context("Config tests", func() {
		Context("Validate", func() {
			var cfg *Config

			BeforeEach(func() {
				cfg = &Config{
					AzureConfigPath:   "path/to/azure.json",
					APIServerFQDN:     "fqdn",
					CustomClientID:    "clientId",
					NextProto:         "alpn",
					AADResource:       "appID",
					ClusterCAFilePath: "path",
					KubeconfigPath:    "path",
					CertFilePath:      "path",
					KeyFilePath:       "path",
					Timeout:           time.Minute,
				}
			})

			When("azureConfigPath is empty", func() {
				It("should return an error", func() {
					cfg.AzureConfigPath = ""
					err := cfg.Validate()
					Expect(err).ToNot(BeNil())
					Expect(err.Error()).To(ContainSubstring("azure config path must be specified"))
				})
			})

			When("ClusterCAFilePath is empty", func() {
				It("should return an error", func() {
					cfg.ClusterCAFilePath = ""
					err := cfg.Validate()
					Expect(err).ToNot(BeNil())
					Expect(err.Error()).To(ContainSubstring("cluster CA file path must be specified"))
				})
			})

			When("APIServerFQDN is empty", func() {
				It("should return an error", func() {
					cfg.APIServerFQDN = ""
					err := cfg.Validate()
					Expect(err).ToNot(BeNil())
					Expect(err.Error()).To(ContainSubstring("apiserver FQDN must be specified"))
				})
			})

			When("NextProto is empty", func() {
				It("should return an error", func() {
					cfg.NextProto = ""
					err := cfg.Validate()
					Expect(err).ToNot(BeNil())
					Expect(err.Error()).To(ContainSubstring("next proto header value must be specified"))
				})
			})

			When("AADResource is empty", func() {
				It("should return an error", func() {
					cfg.AADResource = ""
					err := cfg.Validate()
					Expect(err).ToNot(BeNil())
					Expect(err.Error()).To(ContainSubstring("AAD resource must be specified"))
				})
			})

			When("KubeconfigPath is empty", func() {
				It("should return an error", func() {
					cfg.KubeconfigPath = ""
					err := cfg.Validate()
					Expect(err).ToNot(BeNil())
					Expect(err.Error()).To(ContainSubstring("kubeconfig path must be specified"))
				})
			})

			When("CertFilePath is empty", func() {
				It("should return an error", func() {
					cfg.CertFilePath = ""
					err := cfg.Validate()
					Expect(err).ToNot(BeNil())
					Expect(err.Error()).To(ContainSubstring("cert file path must be specified"))
				})
			})

			When("KeyFilePath is empty", func() {
				It("should return an error", func() {
					cfg.KeyFilePath = ""
					err := cfg.Validate()
					Expect(err).ToNot(BeNil())
					Expect(err.Error()).To(ContainSubstring("key file path must be specified"))
				})
			})

			When("timeout is not specified", func() {
				It("should return an error", func() {
					cfg.Timeout = 0
					err := cfg.Validate()
					Expect(err).ToNot(BeNil())
					Expect(err.Error()).To(ContainSubstring("timeout must be specified"))
				})
			})

			When("azure config path does not exist", func() {
				It("should return an error", func() {
					cfg.AzureConfigPath = "does/not/exist.json"
					err := cfg.Validate()
					Expect(err).ToNot(BeNil())
					Expect(err.Error()).To(ContainSubstring("loading azure config file"))
					Expect(err.Error()).To(ContainSubstring("reading file"))
				})
			})

			When("azure config is malformed", func() {
				It("should return an error", func() {
					tempDir := GinkgoT().TempDir()
					path := filepath.Join(tempDir, "config.json")
					err := os.WriteFile(path, []byte("malformed"), os.ModePerm)
					Expect(err).To(BeNil())
					cfg.AzureConfigPath = path
					err = cfg.Validate()
					Expect(err).ToNot(BeNil())
					Expect(err.Error()).To(ContainSubstring("loading azure config file"))
					Expect(err.Error()).To(ContainSubstring("unmarshalling json data"))
				})
			})

			When("client opts are valid", func() {
				It("should validate without error", func() {
					azureConfig := datamodel.AzureConfig{
						ClientID:               "msi",
						UserAssignedIdentityID: "identityId",
						Cloud:                  azure.PublicCloud.Name,
					}
					configBytes, err := json.Marshal(azureConfig)
					Expect(err).To(BeNil())

					tempDir := GinkgoT().TempDir()
					cfg.AzureConfigPath = filepath.Join(tempDir, "azure.json")

					err = os.WriteFile(cfg.AzureConfigPath, configBytes, os.ModePerm)
					Expect(err).To(BeNil())

					err = cfg.Validate()
					Expect(err).To(BeNil())
					Expect(cfg.AzureConfig).To(Equal(azureConfig))
				})
			})
		})

		Context("LoadFromFile", func() {
			var cfg *Config

			BeforeEach(func() {
				cfg = new(Config)
			})

			When("config file does not exist", func() {
				It("should return an error", func() {
					path := "does/not/exist.json"
					err := cfg.LoadFromFile(path)
					Expect(err).ToNot(BeNil())
					Expect(err.Error()).To(ContainSubstring("loading bootstrap config file"))
					Expect(err.Error()).To(ContainSubstring("reading file"))
				})
			})

			When("config file is malformed", func() {
				It("should return an error", func() {
					tempDir := GinkgoT().TempDir()
					path := filepath.Join(tempDir, "config.json")
					err := os.WriteFile(path, []byte("malformed"), os.ModePerm)
					Expect(err).To(BeNil())
					err = cfg.LoadFromFile(path)
					Expect(err).ToNot(BeNil())
					Expect(err.Error()).To(ContainSubstring("loading bootstrap config file"))
					Expect(err.Error()).To(ContainSubstring("unmarshalling json data"))
				})
			})

			When("config file exists and is valid", func() {
				It("should load from the config file without error", func() {
					config := &Config{
						AzureConfigPath:   "path/to/azure.json",
						APIServerFQDN:     "fqdn",
						CustomClientID:    "clientId",
						NextProto:         "alpn",
						AADResource:       "appID",
						ClusterCAFilePath: "clusterCAPath",
						KubeconfigPath:    "kubeconfigPath",
						CertFilePath:      "certFilePath",
						KeyFilePath:       "keyFilePath",
					}
					tempDir := GinkgoT().TempDir()
					path := filepath.Join(tempDir, "config.json")
					configData, err := json.Marshal(config)
					Expect(err).To(BeNil())
					err = os.WriteFile(path, configData, os.ModePerm)
					Expect(err).To(BeNil())
					err = cfg.LoadFromFile(path)
					Expect(err).To(BeNil())
					Expect(cfg).To(Equal(config))
				})
			})
		})
	})
})
