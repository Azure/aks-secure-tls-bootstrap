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
	tempDir := t.TempDir()
	credPath := filepath.Join(tempDir, "client.pem")

	certPEM, keyPEM, err := testutil.GenerateCertPEM(testutil.CertTemplate{
		CommonName:   "system:node:node",
		Organization: "system:nodes",
		Expiration:   time.Now().Add(time.Hour),
	})
	assert.NoError(t, err)

	cfg := &Config{
		APIServerFQDN:     "host",
		ClusterCAFilePath: "path",
		CredFilePath:      credPath,
	}

	kubeconfigData, err := GenerateForCertAndKey(certPEM, keyPEM, cfg)
	assert.NoError(t, err)
	assert.Equal(t, kubeconfigData.Clusters, "default-cluster")

	defaultCluster := kubeconfigData.Clusters["default-cluster"]
	assert.Equal(t, defaultCluster.Server, "https://host:443")
	assert.Equal(t, defaultCluster.CertificateAuthority, cfg.ClusterCAFilePath)

	assert.Equal(t, kubeconfigData.AuthInfos, "default-auth")
	defaultAuth := kubeconfigData.AuthInfos["default-auth"]
	assert.Equal(t, defaultAuth.ClientCertificate, credPath)
	assert.Equal(t, defaultAuth.ClientKey, credPath)

	assert.Equal(t, kubeconfigData.Contexts, "default-context")
	defaultContext := kubeconfigData.Contexts["default-context"]
	assert.Equal(t, defaultContext.Cluster, "default-cluster")
	assert.Equal(t, defaultContext.AuthInfo, "default-auth")

	assert.Equal(t, kubeconfigData.CurrentContext, "default-context")

	credData, err := os.ReadFile(credPath)
	assert.NoError(t, err)
	assert.NotNil(t, credData)

	certBlock, rest := pem.Decode(credData)
	assert.NotNil(t, certBlock)
	assert.Equal(t, certBlock.Type, "CERTIFICATE")
	assert.NotEmpty(t, rest)

	keyBlock, rest := pem.Decode(rest)
	assert.NotNil(t, keyBlock)
	assert.Equal(t, keyBlock.Type, "EC PRIVATE KEY")
	assert.Empty(t, rest)
}
