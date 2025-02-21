// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package bootstrap

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/Azure/aks-secure-tls-bootstrap/client/internal/datamodel"
)

type Config struct {
	datamodel.AzureConfig
	AzureConfigPath        string        `json:"azureConfigPath"`
	APIServerFQDN          string        `json:"apiServerFqdn"`
	CustomClientID         string        `json:"customClientId"`
	NextProto              string        `json:"nextProto"`
	AADResource            string        `json:"aadResource"`
	ClusterCAFilePath      string        `json:"clusterCaFilePath"`
	KubeconfigPath         string        `json:"kubeconfigPath"`
	CertFilePath           string        `json:"certFilePath"`
	KeyFilePath            string        `json:"keyFilePath"`
	InsecureSkipTLSVerify  bool          `json:"insecureSkipTlsVerify"`
	EnsureAuthorizedClient bool          `json:"ensureAuthorizedClient"`
	Deadline               time.Duration `json:"deadline"`
}

func (c *Config) Validate() error {
	if c.AzureConfigPath == "" {
		return fmt.Errorf("azure config path must be specified")
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
	if c.CertFilePath == "" {
		return fmt.Errorf("cert file path must be specified")
	}
	if c.KeyFilePath == "" {
		return fmt.Errorf("key file path must be specified")
	}
	if c.Deadline == 0 {
		return fmt.Errorf("deadline must be specified")
	}
	return c.loadAzureConfig()
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

func (c *Config) loadAzureConfig() error {
	data, err := os.ReadFile(c.AzureConfigPath)
	if err != nil {
		return fmt.Errorf("reading azure config data: %w", err)
	}
	if err = json.Unmarshal(data, &c.AzureConfig); err != nil {
		return fmt.Errorf("unmarshalling azure config data: %w", err)
	}
	return nil
}
