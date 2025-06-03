// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package bootstrap

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Azure/aks-secure-tls-bootstrap/client/internal/cloud"
	"github.com/Azure/go-autorest/autorest/azure"
	"github.com/stretchr/testify/assert"
)

func TestConfig(t *testing.T) {
	baseCfg := &Config{
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
	tests := []struct {
		name        string
		modify      func(*Config, *testing.T)
		expectedErr string
	}{
		{
			name: "cloudProviderConfigPath is empty",
			modify: func(c *Config, t *testing.T) {
				c.CloudProviderConfigPath = ""
			},
			expectedErr: "cloud provider config path must be specified",
		},
		{
			name: "ClusterCAFilePath is empty",
			modify: func(c *Config, t *testing.T) {
				c.ClusterCAFilePath = ""
			},
			expectedErr: "cluster CA file path must be specified",
		},
		{
			name: "APIServerFQDN is empty",
			modify: func(c *Config, t *testing.T) {
				c.APIServerFQDN = ""
			},
			expectedErr: "apiserver FQDN must be specified",
		},
		{
			name: "NextProto is empty",
			modify: func(c *Config, t *testing.T) {
				c.NextProto = ""
			},
			expectedErr: "next proto header value must be specified",
		},
		{
			name: "AADResource is empty",
			modify: func(c *Config, t *testing.T) {
				c.AADResource = ""
			},
			expectedErr: "AAD resource must be specified",
		},
		{
			name: "KubeconfigPath is empty",
			modify: func(c *Config, t *testing.T) {
				c.KubeconfigPath = ""
			},
			expectedErr: "kubeconfig path must be specified",
		},
		{
			name: "CredFilePath is empty",
			modify: func(c *Config, t *testing.T) {
				c.CredFilePath = ""
			},
			expectedErr: "cred file path must be specified",
		},
		{
			name: "cloud provider config path does not exist",
			modify: func(c *Config, t *testing.T) {
				c.CloudProviderConfigPath = "does/not/exist.json"
			},
			expectedErr: "reading cloud provider config data",
		},
		{
			name: "cloud provider config is malformed",
			modify: func(c *Config, t *testing.T) {
				tempDir := t.TempDir()
				path := filepath.Join(tempDir, "config.json")
				_ = os.WriteFile(path, []byte("malformed"), os.ModePerm)
				c.CloudProviderConfigPath = path
			},
			expectedErr: "unmarshalling cloud provider config data",
		},
		{
			name: "client opts are valid",
			modify: func(c *Config, t *testing.T) {
				config := cloud.ProviderConfig{
					ClientID:               "msi",
					UserAssignedIdentityID: "identityId",
					CloudName:              azure.PublicCloud.Name,
				}
				data, _ := json.Marshal(config)
				tempDir := t.TempDir()
				c.CloudProviderConfigPath = filepath.Join(tempDir, "azure.json")
				_ = os.WriteFile(c.CloudProviderConfigPath, data, os.ModePerm)
			},
			expectedErr: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := *baseCfg
			tt.modify(&cfg, t)

			err := cfg.Validate()
			if tt.expectedErr != "" {
				assert.Error(t,err)
				assert.Contains(t, err.Error(), tt.expectedErr)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, cloud.ProviderConfig{
					ClientID: "msi",
					UserAssignedIdentityID: "identityId",
					CloudName: azure.PublicCloud.Name,
				}, cfg.ProviderConfig)
			}
		})
	}
}

func TestLoadFromFile(t *testing.T) {
	baseCfg := &Config{
		CloudProviderConfigPath: "path/to/azure.json",
		APIServerFQDN:           "fqdn",
		CustomClientID:          "clientId",
		NextProto:               "alpn",
		AADResource:             "appID",
		ClusterCAFilePath:       "path",
		KubeconfigPath:          "path",
		CredFilePath:            "path",
	}
	tests := []struct {
		name        string
		modify      func(*Config, *testing.T)
		expectedErr string
	}{
		{
			name: "config file does not exist",
			modify: func(c *Config, t *testing.T) {
				c.CloudProviderConfigPath = "does/not/exist.json"
			},
			expectedErr: "reading config file",
		},
		{
			name: "config file is malformed",
			modify: func(c *Config, t *testing.T) {
				tempDir := t.TempDir()
				path := filepath.Join(tempDir, "config.json")
				err := os.WriteFile(path, []byte("malformed"), os.ModePerm)
				assert.NoError(t, err)
				c.CloudProviderConfigPath = path
			},
			expectedErr: "unmarshalling config file content",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := *baseCfg
			tt.modify(&cfg, t)

			err := cfg.LoadFromFile(cfg.CloudProviderConfigPath)
			if tt.expectedErr != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedErr)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}