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

func TestConfig(t *testing.T) {
	tests := []struct {
		name        string
		modify      func(*Config, *testing.T)
		expectedErr error
	}{
		{
			name: "cloudProviderConfigPath is empty",
			modify: func(c *Config, t *testing.T) {
				c.CloudProviderConfigPath = ""
			},
			expectedErr: errors.New("cloud provider config path must be specified"),
		},
		{
			name: "ClusterCAFilePath is empty",
			modify: func(c *Config, t *testing.T) {
				c.ClusterCAFilePath = ""
			},
			expectedErr: errors.New("cluster CA file path must be specified"),
		},
		{
			name: "APIServerFQDN is empty",
			modify: func(c *Config, t *testing.T) {
				c.APIServerFQDN = ""
			},
			expectedErr: errors.New("apiserver FQDN must be specified"),
		},
		{
			name: "NextProto is empty",
			modify: func(c *Config, t *testing.T) {
				c.NextProto = ""
			},
			expectedErr: errors.New("next proto header value must be specified"),
		},
		{
			name: "AADResource is empty",
			modify: func(c *Config, t *testing.T) {
				c.AADResource = ""
			},
			expectedErr: errors.New("AAD resource must be specified"),
		},
		{
			name: "KubeconfigPath is empty",
			modify: func(c *Config, t *testing.T) {
				c.KubeconfigPath = ""
			},
			expectedErr: errors.New("kubeconfig path must be specified"),
		},
		{
			name: "CredFilePath is empty",
			modify: func(c *Config, t *testing.T) {
				c.CredFilePath = ""
			},
			expectedErr: errors.New("cred file path must be specified"),
		},
		{
			name: "cloud provider config path does not exist",
			modify: func(c *Config, t *testing.T) {
				c.CloudProviderConfigPath = "does/not/exist.json"
			},
			expectedErr: errors.New("reading cloud provider config data"),
		},
		{
			name: "cloud provider config is malformed",
			modify: func(c *Config, t *testing.T) {
				tempDir := t.TempDir()
				path := filepath.Join(tempDir, "config.json")
				_ = os.WriteFile(path, []byte("malformed"), os.ModePerm)
				c.CloudProviderConfigPath = path
			},
			expectedErr: errors.New("unmarshalling cloud provider config data"),
		},
		{
			name: "client opts are valid",
			modify: func(c *Config, t *testing.T) {
				config := cloud.ProviderConfig{
					ClientID:               "msi",
					UserAssignedIdentityID: "identityId",
					CloudName:              azure.PublicCloud.Name,
				}
				data, err := json.Marshal(config)
				assert.NoError(t, err)
				tempDir := t.TempDir()
				c.CloudProviderConfigPath = filepath.Join(tempDir, "azure.json")
				_ = os.WriteFile(c.CloudProviderConfigPath, data, os.ModePerm)
			},
			expectedErr: errors.New(""),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
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
			cfg := *baseCfg
			tt.modify(&cfg, t)

			err := cfg.Validate()
			if tt.expectedErr != nil {
				assert.Equal(t, err, tt.expectedErr)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, cloud.ProviderConfig{
					ClientID:               "msi",
					UserAssignedIdentityID: "identityId",
					CloudName:              azure.PublicCloud.Name,
				}, cfg.ProviderConfig)
			}
		})
	}
}
func TestLoadFromFile(t *testing.T) {
	tests := []struct {
		name        string
		modify      func(*Config, *testing.T)
		expectedErr error
	}{
		{
			name: "config file does not exist",
			modify: func(c *Config, t *testing.T) {
				c.CloudProviderConfigPath = "does/not/exist.json"
			},
			expectedErr: errors.New("reading config file"),
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
			expectedErr: errors.New("unmarshalling config file content"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
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
			cfg := *baseCfg
			tt.modify(&cfg, t)

			err := cfg.LoadFromFile(cfg.CloudProviderConfigPath)
			if tt.expectedErr != nil {
				assert.Equal(t, tt.expectedErr.Error(), err.Error())
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
