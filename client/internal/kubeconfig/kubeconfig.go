// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package kubeconfig

import (
	"bytes"
	"fmt"
	"os"

	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

// Config is used to configure a newly-generated kubeconfig.
type Config struct {
	APIServerFQDN     string
	ClusterCAFilePath string
	CredFilePath      string
}

// GenerateForCertAndKey generates a valid kubeconfig with the specified cert, key, and configuration.
// The cert and key will have their PEM-encodings written out to a single credential file to be
// referenced within the generated kubeconfig.
func GenerateForCertAndKey(certPEM, keyPEM []byte, cfg *Config) (*clientcmdapi.Config, error) {
	var credBytes bytes.Buffer
	if _, err := credBytes.Write(certPEM); err != nil {
		return nil, fmt.Errorf("writing client cert PEM bytes to buffer: %w", err)
	}
	if _, err := credBytes.Write(keyPEM); err != nil {
		return nil, fmt.Errorf("writing client key PEM bytes to buffer: %w", err)
	}
	if err := os.WriteFile(cfg.CredFilePath, credBytes.Bytes(), 0600); err != nil {
		return nil, fmt.Errorf("failed to write client cert/key pair to %s: %w", cfg.CredFilePath, err)
	}

	kubeconfigData := &clientcmdapi.Config{
		// Define cluster based on the specified apiserver FQDN and cluster CA.
		Clusters: map[string]*clientcmdapi.Cluster{
			"default-cluster": {
				Server:               fmt.Sprintf("https://%s:443", cfg.APIServerFQDN),
				CertificateAuthority: cfg.ClusterCAFilePath,
			},
		},
		// Define auth based on the obtained client cert.
		AuthInfos: map[string]*clientcmdapi.AuthInfo{
			"default-auth": {
				ClientCertificate: cfg.CredFilePath,
				ClientKey:         cfg.CredFilePath,
			},
		},
		// Define a context that connects the auth info and cluster, and set it as the default
		Contexts: map[string]*clientcmdapi.Context{
			"default-context": {
				Cluster:  "default-cluster",
				AuthInfo: "default-auth",
			},
		},
		CurrentContext: "default-context",
	}

	return kubeconfigData, nil
}
