package bootstrap

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/Azure/aks-secure-tls-bootstrap/client/pkg/datamodel"
)

type Config struct {
	APIServerFQDN              string
	CustomClientID             string
	NextProto                  string
	AADResource                string
	ClusterCAFilePath          string
	KubeconfigPath             string
	CertFilePath               string
	KeyFilePath                string
	InsecureSkipTLSVerify      bool
	EnsureClientAuthentication bool
	AzureConfig                *datamodel.AzureConfig
}

func (c *Config) ValidateAndSet(azureConfigPath string) error {
	if azureConfigPath == "" {
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

	azureConfig := &datamodel.AzureConfig{}
	azureConfigData, err := os.ReadFile(azureConfigPath)
	if err != nil {
		return fmt.Errorf("reading azure config data from %s: %w", azureConfigPath, err)
	}
	if err = json.Unmarshal(azureConfigData, azureConfig); err != nil {
		return fmt.Errorf("unmarshaling azure config data: %w", err)
	}
	c.AzureConfig = azureConfig

	return nil
}
