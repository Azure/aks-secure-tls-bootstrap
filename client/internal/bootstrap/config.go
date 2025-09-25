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
	CloudProviderConfig     *cloud.ProviderConfig
	CloudProviderConfigPath string        `json:"cloudProviderConfigPath"`
	APIServerFQDN           string        `json:"apiServerFqdn"`
	UserAssignedIdentityID  string        `json:"userAssignedIdentityId"`
	NextProto               string        `json:"nextProto"`
	AADResource             string        `json:"aadResource"`
	ClusterCAFilePath       string        `json:"clusterCaFilePath"`
	KubeconfigPath          string        `json:"kubeconfigPath"`
	CertDir                 string        `json:"credFilePath"`
	InsecureSkipTLSVerify   bool          `json:"insecureSkipTlsVerify"`
	EnsureAuthorizedClient  bool          `json:"ensureAuthorizedClient"`
	Deadline                time.Duration `json:"deadline"`
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

func (c *Config) DefaultAndValidate() error {
	c.applyDefaults()
	return c.validate()
}

func (c *Config) applyDefaults() {
	if c.Deadline == 0 {
		c.Deadline = 2 * time.Minute
	}
}

func (c *Config) validate() error {
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

	if c.CloudProviderConfigPath == "" {
		return fmt.Errorf("cloud provider config path must be specified")
	}
	data, err := os.ReadFile(c.CloudProviderConfigPath)
	if err != nil {
		return fmt.Errorf("cannot read cloud provider config data: %w", err)
	}
	c.CloudProviderConfig = new(cloud.ProviderConfig)
	if err = json.Unmarshal(data, c.CloudProviderConfig); err != nil {
		return fmt.Errorf("cannot unmarshal cloud provider config data: %w", err)
	}

	if c.ClusterCAFilePath == "" {
		return fmt.Errorf("cluster CA file path must be specified")
	}
	if _, err := os.Stat(c.ClusterCAFilePath); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("specified cluster CA file does not exist: %s", c.ClusterCAFilePath)
		}
		return fmt.Errorf("unable to verify existence of cluster CA file: %w", err)
	}

	return nil
}
