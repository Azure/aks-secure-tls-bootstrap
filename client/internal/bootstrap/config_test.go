// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package bootstrap

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	"github.com/Azure/aks-secure-tls-bootstrap/client/internal/cloud"
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
					CloudProviderConfigPath: "path/to/azure.json",
					APIServerFQDN:           "fqdn",
					CustomClientID:          "clientId",
					NextProto:               "alpn",
					AADResource:             "appID",
					ClusterCAFilePath:       "path",
					KubeconfigPath:          "path",
					CredFilePath:            "path",
					Deadline:                time.Second,
				}
			})

			When("cloudProviderConfigPath is empty", func() {
				It("should return an error", func() {
					cfg.CloudProviderConfigPath = ""
					err := cfg.Validate()
					Expect(err).ToNot(BeNil())
					Expect(err.Error()).To(ContainSubstring("cloud provider config path must be specified"))
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

			When("CredFilePath is empty", func() {
				It("should return an error", func() {
					cfg.CredFilePath = ""
					err := cfg.Validate()
					Expect(err).ToNot(BeNil())
					Expect(err.Error()).To(ContainSubstring("cred file path must be specified"))
				})
			})

			When("cloud provider config path does not exist", func() {
				It("should return an error", func() {
					cfg.CloudProviderConfigPath = "does/not/exist.json"
					err := cfg.Validate()
					Expect(err).ToNot(BeNil())
					Expect(err.Error()).To(ContainSubstring("reading cloud provider config data"))
				})
			})

			When("cloud provider config is malformed", func() {
				It("should return an error", func() {
					tempDir := GinkgoT().TempDir()
					path := filepath.Join(tempDir, "config.json")
					err := os.WriteFile(path, []byte("malformed"), os.ModePerm)
					Expect(err).To(BeNil())
					cfg.CloudProviderConfigPath = path
					err = cfg.Validate()
					Expect(err).ToNot(BeNil())
					Expect(err.Error()).To(ContainSubstring("unmarshalling cloud provider config data"))
				})
			})

			When("client opts are valid", func() {
				It("should validate without error", func() {
					cloudProviderConfig := cloud.ProviderConfig{
						ClientID:               "msi",
						UserAssignedIdentityID: "identityId",
						CloudName:              azure.PublicCloud.Name,
					}
					configBytes, err := json.Marshal(cloudProviderConfig)
					Expect(err).To(BeNil())

					tempDir := GinkgoT().TempDir()
					cfg.CloudProviderConfigPath = filepath.Join(tempDir, "azure.json")

					err = os.WriteFile(cfg.CloudProviderConfigPath, configBytes, os.ModePerm)
					Expect(err).To(BeNil())

					err = cfg.Validate()
					Expect(err).To(BeNil())
					Expect(cfg.ProviderConfig).To(Equal(cloudProviderConfig))
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
					Expect(err.Error()).To(ContainSubstring("reading config file"))
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
					Expect(err.Error()).To(ContainSubstring("unmarshalling config file content"))
				})
			})

			When("config file exists and is valid", func() {
				It("should load from the config file without error", func() {
					config := &Config{
						CloudProviderConfigPath: "path/to/azure.json",
						APIServerFQDN:           "fqdn",
						CustomClientID:          "clientId",
						NextProto:               "alpn",
						AADResource:             "appID",
						ClusterCAFilePath:       "clusterCAPath",
						KubeconfigPath:          "kubeconfigPath",
						CredFilePath:            "credFilePath",
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
