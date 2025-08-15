// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package bootstrap

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/Azure/aks-secure-tls-bootstrap/client/internal/cloud"
)

type Config struct {
	cloud.ProviderConfig

	CloudProviderConfigPath string        `json:"cloudProviderConfigPath"`
	APIServerFQDN           string        `json:"apiServerFqdn"`
	CustomClientID          string        `json:"customClientId"`
	NextProto               string        `json:"nextProto"`
	AADResource             string        `json:"aadResource"`
	ClusterCAFilePath       string        `json:"clusterCaFilePath"`
	KubeconfigPath          string        `json:"kubeconfigPath"`
	CertDir                 string        `json:"credFilePath"`
	InsecureSkipTLSVerify   bool          `json:"insecureSkipTlsVerify"`
	EnsureAuthorizedClient  bool          `json:"ensureAuthorizedClient"`
	Deadline                time.Duration `json:"deadline"`
}

func (c *Config) Validate() error {
	if c.CloudProviderConfigPath == "" {
		return fmt.Errorf("cloud provider config path must be specified")
	}
	if c.ClusterCAFilePath == "" {
		return fmt.Errorf("cluster CA file path must be specified")
	}
	if c.APIServerFQDN == "" {
		return fmt.Errorf("apiserver FQDN must be specified")
	}
	if c.NextProto == "" {
		return fmt.Errorf("next proto header value must be specified")
	}
	if c.AADResource == "" {
		return fmt.Errorf("AAD resource must be specified")
	}
	if c.KubeconfigPath == "" {
		return fmt.Errorf("kubeconfig path must be specified")
	}
	if c.CertDir == "" {
		return fmt.Errorf("cert dir must be specified")
	}
	if c.Deadline == 0 {
		return fmt.Errorf("deadline must be specified")
	}
	return c.loadCloudProviderConfig()
}

func (c *Config) LoadFromFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading config file: %w", err)
	}
	if err := json.Unmarshal(data, c); err != nil {
		return fmt.Errorf("unmarshalling config file content: %w", err)
	}
	return nil
}

func (c *Config) loadCloudProviderConfig() error {
	data, err := os.ReadFile(c.CloudProviderConfigPath)
	if err != nil {
		return fmt.Errorf("reading cloud provider config data: %w", err)
	}
	if err = json.Unmarshal(data, &c.ProviderConfig); err != nil {
		return fmt.Errorf("unmarshalling cloud provider config data: %w", err)
	}
	return nil
}
