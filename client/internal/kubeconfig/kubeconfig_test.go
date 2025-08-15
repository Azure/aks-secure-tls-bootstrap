// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package kubeconfig

import (
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Azure/aks-secure-tls-bootstrap/client/internal/testutil"
	"github.com/stretchr/testify/assert"
)

func TestKubeconfigGeneration(t *testing.T) {
	originalKubeletClientCertFileName := kubeletClientCertFileName
	t.Cleanup(func() {
		kubeletClientCertFileName = originalKubeletClientCertFileName
	})

	tempDir := t.TempDir()
	kubeletClientCertFileName = func() string {
		return "kubelet-client-test.pem"
	}
	certPath := filepath.Join(tempDir, kubeletClientCertFileName())

	certPEM, keyPEM, err := testutil.GenerateCertPEM(testutil.CertTemplate{
		CommonName:   "system:node:node",
		Organization: "system:nodes",
		Expiration:   time.Now().Add(time.Hour),
	})
	assert.NoError(t, err)

	cfg := &Config{
		APIServerFQDN:     "host",
		ClusterCAFilePath: "path",
		CertDir:           tempDir,
	}

	kubeconfigData, err := GenerateForCertAndKey(certPEM, keyPEM, cfg)
	assert.NoError(t, err)
	assert.Contains(t, kubeconfigData.Clusters, "default-cluster")
	defaultCluster := kubeconfigData.Clusters["default-cluster"]
	assert.Equal(t, "https://host:443", defaultCluster.Server)
	assert.Equal(t, cfg.ClusterCAFilePath, defaultCluster.CertificateAuthority)

	assert.Contains(t, kubeconfigData.AuthInfos, "default-auth")
	defaultAuth := kubeconfigData.AuthInfos["default-auth"]
	assert.Equal(t, certPath, defaultAuth.ClientCertificate)
	assert.Equal(t, certPath, defaultAuth.ClientKey)
	assert.Contains(t, kubeconfigData.Contexts, "default-context")
	defaultContext := kubeconfigData.Contexts["default-context"]
	assert.Equal(t, "default-cluster", defaultContext.Cluster)
	assert.Equal(t, "default-auth", defaultContext.AuthInfo)
	assert.Equal(t, "default-context", kubeconfigData.CurrentContext)

	certData, err := os.ReadFile(certPath)
	assert.NoError(t, err)
	assert.NotNil(t, certData)

	certBlock, rest := pem.Decode(certData)
	assert.NotNil(t, certBlock)
	assert.Equal(t, "CERTIFICATE", certBlock.Type)
	assert.NotEmpty(t, certBlock.Bytes)
	assert.NotEmpty(t, rest)

	keyBlock, rest := pem.Decode(rest)
	assert.NotNil(t, keyBlock)
	assert.Equal(t, "EC PRIVATE KEY", keyBlock.Type)
	assert.Empty(t, rest)
}
