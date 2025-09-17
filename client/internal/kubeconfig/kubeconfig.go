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

const (
	kubeletClientCurrentSymlinkName = "kubelet-client-current.pem"
)

// Config is used to configure a newly-generated kubeconfig.
type Config struct {
	APIServerFQDN     string
	ClusterCAFilePath string
	CertDir           string
}

// GenerateForCertAndKey generates a valid kubeconfig with the specified cert, key, and configuration.
// The cert and key will have their PEM-encodings written out to a single pair file to be
// referenced within the generated kubeconfig. If needed, a kubelet-client-current.pem symlink
// will also be created, pointing to the newly-created cert file to emulate kubelet's TLS bootstrapping behavior.
func GenerateForCertAndKey(certPEM, keyPEM []byte, config *Config) (*clientcmdapi.Config, error) {
	certPath, err := createClientCertFile(certPEM, keyPEM, config.CertDir)
	if err != nil {
		return nil, fmt.Errorf("creating kubelet client cert file: %w", err)
	}

	currentPath, err := createCurrentClientSymlink(config.CertDir, certPath)
	if err != nil {
		return nil, fmt.Errorf("creating kubelet client current symlink: %w", err)
	}

	kubeconfigData := &clientcmdapi.Config{
		// define cluster based on the specified apiserver FQDN and cluster CA
		Clusters: map[string]*clientcmdapi.Cluster{
			"default-cluster": {
				Server:               fmt.Sprintf("https://%s:443", config.APIServerFQDN),
				CertificateAuthority: config.ClusterCAFilePath,
			},
		},
		// define auth based on the obtained client cert
		AuthInfos: map[string]*clientcmdapi.AuthInfo{
			"default-auth": {
				ClientCertificate: currentPath,
				ClientKey:         currentPath,
			},
		},
		// define a context that connects the auth info and cluster, and set it as the default
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

func createClientCertFile(certPEM, keyPEM []byte, certDir string) (string, error) {
	var certBuf bytes.Buffer
	if _, err := certBuf.Write(certPEM); err != nil {
		return "", fmt.Errorf("writing kubelet client cert PEM bytes to buffer: %w", err)
	}
	if _, err := certBuf.Write(keyPEM); err != nil {
		return "", fmt.Errorf("writing kubelet client key PEM bytes to buffer: %w", err)
	}

	certPath := filepath.Join(certDir, getKubeletClientCertFileName())
	if err := os.MkdirAll(certDir, 0755); err != nil {
		return "", fmt.Errorf("creating kubelet cert dir: %w", err)
	}
	if err := os.WriteFile(certPath, certBuf.Bytes(), 0600); err != nil {
		return "", fmt.Errorf("failed to write kubelet client cert/key pair to %s: %w", certPath, err)
	}

	return certPath, nil
}

// createCurrentClientSymlink creates a symlink at certDir/kubelet-client-current.pem that points to the specified certPath.
// Any existing kubelet client current symlink will be replaced with a new pointing to certPath.
func createCurrentClientSymlink(certDir, certPath string) (string, error) {
	symlinkPath := filepath.Join(certDir, kubeletClientCurrentSymlinkName)
	if _, err := os.Lstat(symlinkPath); err == nil {
		// remove the existing symlink if needed
		if err := os.Remove(symlinkPath); err != nil {
			return "", fmt.Errorf("removing existing kubelet client current symlink: %w", err)
		}
	} else if !os.IsNotExist(err) {
		return "", fmt.Errorf("checking for existing kubelet client current symlink: %w", err)
	}

	if err := os.Symlink(certPath, symlinkPath); err != nil {
		return "", fmt.Errorf("creating kubelet client current symlink: %w", err)
	}

	return symlinkPath, nil
}

func getKubeletClientCertFileName() string {
	// to emulate kubelet's TLS bootstrapping behavior - see FileStore implementation within client-go/util/certificate:
	// https://github.com/kubernetes/client-go/blob/d99dd130a2fc7519c0bc2bd7271447b2a16c04a2/util/certificate/certificate_store.go#L205
	return fmt.Sprintf("kubelet-client-%s.pem", time.Now().Format("2006-01-02-15-04-05"))
}
