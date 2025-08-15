// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package kubeconfig

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Azure/aks-secure-tls-bootstrap/client/internal/testutil"
	"github.com/stretchr/testify/assert"
)

func TestKubeconfigGeneration(t *testing.T) {
	certPEM, keyPEM, err := testutil.GenerateCertPEM(testutil.CertTemplate{
		CommonName:   "system:node:node",
		Organization: "system:nodes",
		Expiration:   time.Now().Add(time.Hour),
	})
	assert.NoError(t, err)

	config := &Config{
		APIServerFQDN:     "host",
		ClusterCAFilePath: "path",
		CertDir:           t.TempDir(),
	}

	kubeconfigData, err := GenerateForCertAndKey(certPEM, keyPEM, config)
	assert.NoError(t, err)

	defaultCluster := kubeconfigData.Clusters["default-cluster"]
	assert.NotNil(t, defaultCluster)
	assert.Equal(t, "https://host:443", defaultCluster.Server)
	assert.Equal(t, config.ClusterCAFilePath, defaultCluster.CertificateAuthority)

	defaultAuth := kubeconfigData.AuthInfos["default-auth"]
	assert.NotNil(t, defaultAuth)
	assert.Equal(t, defaultAuth.ClientCertificate, defaultAuth.ClientKey)
	assert.Equal(t, config.CertDir, filepath.Dir(defaultAuth.ClientCertificate))

	defaultContext := kubeconfigData.Contexts["default-context"]
	assert.NotNil(t, defaultContext)
	assert.Equal(t, "default-cluster", defaultContext.Cluster)
	assert.Equal(t, "default-auth", defaultContext.AuthInfo)

	assert.Equal(t, "default-context", kubeconfigData.CurrentContext)

	certData, err := os.ReadFile(defaultAuth.ClientCertificate)
	assert.NoError(t, err)
	assert.NotNil(t, certData)

	certBlock, rest := pem.Decode(certData)
	assert.NotNil(t, certBlock)
	assert.NotEmpty(t, rest)
	assert.Equal(t, "CERTIFICATE", certBlock.Type)

	cert, err := x509.ParseCertificate(certBlock.Bytes)
	assert.NoError(t, err)
	assert.NotNil(t, cert)
	assert.Equal(t, "system:node:node", cert.Subject.CommonName)
	assert.Equal(t, []string{"system:nodes"}, cert.Subject.Organization)

	keyBlock, rest := pem.Decode(rest)
	assert.NotNil(t, keyBlock)
	assert.Empty(t, rest)
	assert.Equal(t, "EC PRIVATE KEY", keyBlock.Type)

	key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	assert.NoError(t, err)
	assert.NotNil(t, key)
}
