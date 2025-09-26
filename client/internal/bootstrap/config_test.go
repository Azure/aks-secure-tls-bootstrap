// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package bootstrap

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Azure/aks-secure-tls-bootstrap/client/internal/cloud"
	"github.com/Azure/go-autorest/autorest/azure"
	"github.com/stretchr/testify/assert"
)

func TestConfigDefaultAndValidate(t *testing.T) {
	cases := []struct {
		name                string
		setupConfig         func(t *testing.T, c *Config)
		expectCorrectConfig func(t *testing.T, c *Config)
		expectedErr         error
	}{
		{
			name: "APIServerFQDN is empty",
			setupConfig: func(t *testing.T, c *Config) {
				c.APIServerFQDN = ""
			},
			expectedErr: errors.New("apiserver FQDN must be specified"),
		},
		{
			name: "NextProto is empty",
			setupConfig: func(t *testing.T, c *Config) {
				c.NextProto = ""
			},
			expectedErr: errors.New("next proto header value must be specified"),
		},
		{
			name: "AADResource is empty",
			setupConfig: func(t *testing.T, c *Config) {
				c.AADResource = ""
			},
			expectedErr: errors.New("AAD resource must be specified"),
		},
		{
			name: "KubeconfigPath is empty",
			setupConfig: func(t *testing.T, c *Config) {
				c.KubeconfigPath = ""
			},
			expectedErr: errors.New("kubeconfig path must be specified"),
		},
		{
			name: "CertDir is empty",
			setupConfig: func(t *testing.T, c *Config) {
				c.CertDir = ""
			},
			expectedErr: errors.New("cert dir must be specified"),
		},
		{
			name: "CloudProviderConfigPath is empty",
			setupConfig: func(t *testing.T, c *Config) {
				c.CloudProviderConfigPath = ""
			},
			expectedErr: errors.New("cloud provider config path must be specified"),
		},
		{
			name: "CloudProviderConfigPath does not exist",
			setupConfig: func(t *testing.T, c *Config) {
				c.CloudProviderConfigPath = "does/not/exist.json"
			},
			expectedErr: errors.New("cannot read cloud provider config data"),
		},
		{
			name: "CloudProviderConfigPath content is malformed",
			setupConfig: func(t *testing.T, c *Config) {
				tempDir := t.TempDir()
				path := filepath.Join(tempDir, "azure.json")
				_ = os.WriteFile(path, []byte("malformed"), os.ModePerm)
				c.CloudProviderConfigPath = path
			},
			expectedErr: errors.New("cannot unmarshal cloud provider config data"),
		},
		{
			name: "ClusterCAFilePath is empty",
			setupConfig: func(t *testing.T, c *Config) {
				tempDir := t.TempDir()

				cloudProviderConfig := cloud.ProviderConfig{
					ClientID:               "msi",
					UserAssignedIdentityID: "identityId",
					CloudName:              azure.PublicCloud.Name,
				}
				cloudProviderConfigBytes, err := json.Marshal(cloudProviderConfig)
				assert.NoError(t, err)

				c.CloudProviderConfigPath = filepath.Join(tempDir, "azure.json")
				err = os.WriteFile(c.CloudProviderConfigPath, cloudProviderConfigBytes, os.ModePerm)
				assert.NoError(t, err)

				c.ClusterCAFilePath = ""
			},
			expectedErr: errors.New("cluster CA file path must be specified"),
		},
		{
			name: "ClusterCAFilePath does not exist",
			setupConfig: func(t *testing.T, c *Config) {
				tempDir := t.TempDir()

				cloudProviderConfig := cloud.ProviderConfig{
					ClientID:               "msi",
					UserAssignedIdentityID: "identityId",
					CloudName:              azure.PublicCloud.Name,
				}
				cloudProviderConfigBytes, err := json.Marshal(cloudProviderConfig)
				assert.NoError(t, err)

				c.CloudProviderConfigPath = filepath.Join(tempDir, "azure.json")
				err = os.WriteFile(c.CloudProviderConfigPath, cloudProviderConfigBytes, os.ModePerm)
				assert.NoError(t, err)

				c.ClusterCAFilePath = "does/not/exist.json"
			},
			expectedErr: errors.New("specified cluster CA file does not exist"),
		},
		{
			name: "ok",
			setupConfig: func(t *testing.T, c *Config) {
				tempDir := t.TempDir()

				cloudProviderConfig := cloud.ProviderConfig{
					ClientID:               "msi",
					UserAssignedIdentityID: "identityId",
					CloudName:              azure.PublicCloud.Name,
				}
				cloudProviderConfigBytes, err := json.Marshal(cloudProviderConfig)
				assert.NoError(t, err)

				c.CloudProviderConfigPath = filepath.Join(tempDir, "azure.json")
				err = os.WriteFile(c.CloudProviderConfigPath, cloudProviderConfigBytes, os.ModePerm)
				assert.NoError(t, err)

				clusterCABytes := []byte("CADATA")
				c.ClusterCAFilePath = filepath.Join(tempDir, "ca.crt")
				err = os.WriteFile(c.ClusterCAFilePath, clusterCABytes, os.ModePerm)
				assert.NoError(t, err)
			},
			expectCorrectConfig: func(t *testing.T, c *Config) {
				assert.Equal(t, &cloud.ProviderConfig{
					ClientID:               "msi",
					UserAssignedIdentityID: "identityId",
					CloudName:              azure.PublicCloud.Name,
				}, c.CloudProviderConfig)
				assert.Equal(t, 2*time.Minute, c.Deadline)
			},
			expectedErr: nil,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			config := &Config{
				CloudProviderConfigPath: "path/to/azure.json",
				APIServerFQDN:           "fqdn",
				UserAssignedIdentityID:  "clientId",
				NextProto:               "alpn",
				AADResource:             "appID",
				ClusterCAFilePath:       "path",
				KubeconfigPath:          "path",
				CertDir:                 "path",
			}
			c.setupConfig(t, config)

			err := config.DefaultAndValidate()
			if c.expectedErr != nil {
				assert.ErrorContains(t, err, c.expectedErr.Error())
			} else {
				assert.NoError(t, err)
				if c.expectCorrectConfig != nil {
					c.expectCorrectConfig(t, config)
				}
			}
		})
	}
}

func TestLoadFromFile(t *testing.T) {
	cases := []struct {
		name            string
		setupConfigFile func(t *testing.T, c *Config) string
		expectedErr     error
	}{
		{
			name: "config file does not exist",
			setupConfigFile: func(t *testing.T, c *Config) string {
				return "does/not/exist.json"
			},
			expectedErr: errors.New("reading config file"),
		},
		{
			name: "config file is malformed",
			setupConfigFile: func(t *testing.T, c *Config) string {
				tempDir := t.TempDir()
				path := filepath.Join(tempDir, "config.json")
				err := os.WriteFile(path, []byte("malformed"), os.ModePerm)
				assert.NoError(t, err)
				return filepath.Join(tempDir, "config.json")
			},
			expectedErr: errors.New("unmarshalling config file content"),
		},
		{
			name: "ok",
			setupConfigFile: func(t *testing.T, c *Config) string {
				tempDir := t.TempDir()

				cloudProviderConfig := cloud.ProviderConfig{
					ClientID:               "msi",
					UserAssignedIdentityID: "identityId",
					CloudName:              azure.PublicCloud.Name,
				}
				cloudProviderConfigBytes, err := json.Marshal(cloudProviderConfig)
				assert.NoError(t, err)

				c.CloudProviderConfigPath = filepath.Join(tempDir, "azure.json")
				err = os.WriteFile(c.CloudProviderConfigPath, cloudProviderConfigBytes, os.ModePerm)
				assert.NoError(t, err)

				clusterCABytes := []byte("CADATA")
				c.ClusterCAFilePath = filepath.Join(tempDir, "ca.crt")
				err = os.WriteFile(c.ClusterCAFilePath, clusterCABytes, os.ModePerm)
				assert.NoError(t, err)

				config := &Config{
					CloudProviderConfigPath: filepath.Join(tempDir, "azure.json"),
					ClusterCAFilePath:       filepath.Join(tempDir, "ca.crt"),
					APIServerFQDN:           "fqdn",
					UserAssignedIdentityID:  "clientId",
					NextProto:               "alpn",
					AADResource:             "appID",
					KubeconfigPath:          "path",
					CertDir:                 "path",
				}
				configBytes, err := json.Marshal(config)
				assert.NoError(t, err)

				configFilePath := filepath.Join(tempDir, "config.json")
				err = os.WriteFile(configFilePath, configBytes, os.ModePerm)
				assert.NoError(t, err)

				return configFilePath
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			config := &Config{
				CloudProviderConfigPath: "path/to/azure.json",
				APIServerFQDN:           "fqdn",
				UserAssignedIdentityID:  "clientId",
				NextProto:               "alpn",
				AADResource:             "appID",
				ClusterCAFilePath:       "path",
				KubeconfigPath:          "path",
				CertDir:                 "path",
			}
			configFilePath := c.setupConfigFile(t, config)

			err := config.LoadFromFile(configFilePath)
			if c.expectedErr != nil {
				assert.ErrorContains(t, err, c.expectedErr.Error())
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
