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
	Timeout                time.Duration `json:"timeout"`
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
	if c.Timeout == 0 {
		return fmt.Errorf("timeout must be specified")
	}
	return c.loadAzureConfig()
}

func (c *Config) LoadFromFile(path string) error {
	if err := loadJSON(path, c); err != nil {
		return fmt.Errorf("loading bootstrap config file: %w", err)
	}
	return nil
}

func (c *Config) loadAzureConfig() error {
	if err := loadJSON(c.AzureConfigPath, &c.AzureConfig); err != nil {
		return fmt.Errorf("loading azure config file: %w", err)
	}
	return nil
}

func loadJSON(path string, out interface{}) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading file %s path: %w", path, err)
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("unmarshalling json data from %s: %w", path, err)
	}
	return nil
}
