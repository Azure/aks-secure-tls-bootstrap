// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package kubeconfig

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

// Config is used to configure a newly-generated kubeconfig.
type Config struct {
	APIServerFQDN     string
	ClusterCAFilePath string
	CertFilePath      string
	KeyFilePath       string
}

// GenerateForCertAndKey generates a valid kubeconfig with the specified cert, key, and configuration.
// The cert and key will have their PEM-encodings written out to respective cert and key files to be
// referenced within the generated kubeconfig.
func GenerateForCertAndKey(certPEM []byte, privateKey *ecdsa.PrivateKey, cfg *Config) (*clientcmdapi.Config, error) {
	keyDER, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("unable to marshal EC private key during kubeconfig generation: %w", err)
	}
	block := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: keyDER,
	}
	keyPEM := pem.EncodeToMemory(block)

	if err = os.WriteFile(cfg.CertFilePath, certPEM, 0644); err != nil {
		return nil, fmt.Errorf("failed to write new client certificate to %s: %w", cfg.CertFilePath, err)
	}

	if err = os.WriteFile(cfg.KeyFilePath, keyPEM, 0600); err != nil {
		return nil, fmt.Errorf("failed to write new client key to %s: %w", cfg.KeyFilePath, err)
	}

	kubeconfigData := &clientcmdapi.Config{
		Clusters: map[string]*clientcmdapi.Cluster{"default-cluster": {
			Server:               fmt.Sprintf("https://%s:443", cfg.APIServerFQDN),
			CertificateAuthority: cfg.ClusterCAFilePath,
		}},
		// Define auth based on the obtained client cert.
		AuthInfos: map[string]*clientcmdapi.AuthInfo{"default-auth": {
			ClientCertificate: cfg.CertFilePath,
			ClientKey:         cfg.KeyFilePath,
		}},
		// Define a context that connects the auth info and cluster, and set it as the default
		Contexts: map[string]*clientcmdapi.Context{"default-context": {
			Cluster:  "default-cluster",
			AuthInfo: "default-auth",
		}},
		CurrentContext: "default-context",
	}

	return kubeconfigData, nil
}
