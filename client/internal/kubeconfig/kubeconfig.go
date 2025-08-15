// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package kubeconfig

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"time"

	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

// Config is used to configure a newly-generated kubeconfig.
type Config struct {
	APIServerFQDN     string
	ClusterCAFilePath string
	CertDir           string
}

// GenerateForCertAndKey generates a valid kubeconfig with the specified cert, key, and configuration.
// The cert and key will have their PEM-encodings written out to a single credential file to be
// referenced within the generated kubeconfig.
func GenerateForCertAndKey(certPEM, keyPEM []byte, cfg *Config) (*clientcmdapi.Config, error) {
	var certBuf bytes.Buffer
	if _, err := certBuf.Write(certPEM); err != nil {
		return nil, fmt.Errorf("writing kubelet client cert PEM bytes to buffer: %w", err)
	}
	if _, err := certBuf.Write(keyPEM); err != nil {
		return nil, fmt.Errorf("writing kubelet client key PEM bytes to buffer: %w", err)
	}

	certPath := filepath.Join(cfg.CertDir, getKubeletClientCertFileName())
	if err := os.MkdirAll(cfg.CertDir, 0755); err != nil {
		return nil, fmt.Errorf("creating kubelet cert dir: %w", err)
	}
	if err := os.WriteFile(certPath, certBuf.Bytes(), 0600); err != nil {
		return nil, fmt.Errorf("failed to write kubelet client cert/key pair to %s: %w", certPath, err)
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
				ClientCertificate: certPath,
				ClientKey:         certPath,
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

func getKubeletClientCertFileName() string {
	// to emulate kubelet's TLS bootstrapping behavior - see FileStore implementation within client-go/util/certificate:
	// https://github.com/kubernetes/client-go/blob/d99dd130a2fc7519c0bc2bd7271447b2a16c04a2/util/certificate/certificate_store.go#L205
	return fmt.Sprintf("kubelet-client-%s.pem", time.Now().Format("2006-01-02-15-04-05"))
}
