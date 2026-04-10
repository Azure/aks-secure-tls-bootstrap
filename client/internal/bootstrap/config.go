// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package bootstrap

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/Azure/aks-secure-tls-bootstrap/client/internal/cloud"
	"go.uber.org/zap"
)

const (
	defaultTLSMinVersion             = "1.3"
	defaultValidateKubeconfigTimeout = 15 * time.Second
	defaultGetAccessTokenTimeout     = time.Minute
	defaultGetInstanceDataTimeout    = 15 * time.Second
	defaultGetNonceTimeout           = 15 * time.Second
	defaultGetAttestedDataTimeout    = 15 * time.Second
	defaultGetCredentialTimeout      = 6 * time.Minute
)

type Config struct {
	CloudProviderConfig       *cloud.ProviderConfig
	CloudProviderConfigPath   string        `json:"cloudProviderConfigPath"`
	APIServerFQDN             string        `json:"apiServerFqdn"`
	UserAssignedIdentityID    string        `json:"userAssignedIdentityId"`
	NextProto                 string        `json:"nextProto"`
	AADResource               string        `json:"aadResource"`
	ClusterCAFilePath         string        `json:"clusterCaFilePath"`
	KubeconfigPath            string        `json:"kubeconfigPath"`
	CertDir                   string        `json:"certDir"`
	TLSMinVersion             string        `json:"tlsMinVersion"`
	InsecureSkipTLSVerify     bool          `json:"insecureSkipTlsVerify"`
	EnsureAuthorizedClient    bool          `json:"ensureAuthorizedClient"`
	ValidateKubeconfigTimeout time.Duration `json:"validateKubeconfigTimeout"`
	GetAccessTokenTimeout     time.Duration `json:"getAccessTokenTimeout"`
	GetInstanceDataTimeout    time.Duration `json:"getInstanceDataTimeout"`
	GetNonceTimeout           time.Duration `json:"getNonceTimeout"`
	GetAttestedDataTimeout    time.Duration `json:"getAttestedDataTimeout"`
	GetCredentialTimeout      time.Duration `json:"getCredentialTimeout"`

	// Deadline is now deprecated and will not be respected.
	// Use per-RPC timeouts instead.
	Deadline time.Duration `json:"deadline"`
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

func (c *Config) ToZapFields() []zap.Field {
	return []zap.Field{
		zap.String("cloudProviderConfigPath", c.CloudProviderConfigPath),
		zap.String("apiServerFqdn", c.APIServerFQDN),
		zap.String("userAssignedIdentityId", c.UserAssignedIdentityID),
		zap.String("nextProto", c.NextProto),
		zap.String("aadResource", c.AADResource),
		zap.String("clusterCaFilePath", c.ClusterCAFilePath),
		zap.String("kubeconfigPath", c.KubeconfigPath),
		zap.String("certDir", c.CertDir),
		zap.String("tlsMinVersion", c.TLSMinVersion),
		zap.Bool("insecureSkipTlsVerify", c.InsecureSkipTLSVerify),
		zap.Bool("ensureAuthorizedClient", c.EnsureAuthorizedClient),
		zap.Int64("validateKubeconfigTimeoutMilliseconds", c.ValidateKubeconfigTimeout.Milliseconds()),
		zap.Int64("getAccessTokenTimeoutMilliseconds", c.GetAccessTokenTimeout.Milliseconds()),
		zap.Int64("getInstanceDataTimeoutMilliseconds", c.GetInstanceDataTimeout.Milliseconds()),
		zap.Int64("getNonceTimeoutMilliseconds", c.GetNonceTimeout.Milliseconds()),
		zap.Int64("getAttestedDataTimeoutMilliseconds", c.GetAttestedDataTimeout.Milliseconds()),
		zap.Int64("getCredentialTimeoutMilliseconds", c.GetCredentialTimeout.Milliseconds()),
		zap.Int64("deadlineMilliseconds", c.Deadline.Milliseconds()),
	}
}

func (c *Config) applyDefaults() {
	if c.TLSMinVersion == "" {
		c.TLSMinVersion = defaultTLSMinVersion
	}
	if c.ValidateKubeconfigTimeout == 0 {
		c.ValidateKubeconfigTimeout = defaultValidateKubeconfigTimeout
	}
	if c.GetAccessTokenTimeout == 0 {
		c.GetAccessTokenTimeout = defaultGetAccessTokenTimeout
	}
	if c.GetInstanceDataTimeout == 0 {
		c.GetInstanceDataTimeout = defaultGetInstanceDataTimeout
	}
	if c.GetNonceTimeout == 0 {
		c.GetNonceTimeout = defaultGetNonceTimeout
	}
	if c.GetAttestedDataTimeout == 0 {
		c.GetAttestedDataTimeout = defaultGetAttestedDataTimeout
	}
	if c.GetCredentialTimeout == 0 {
		c.GetCredentialTimeout = defaultGetCredentialTimeout
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
	if c.TLSMinVersion != "1.2" && c.TLSMinVersion != "1.3" {
		return fmt.Errorf(`when specified, TLS min version can either be "1.2" or "1.3"`)
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
