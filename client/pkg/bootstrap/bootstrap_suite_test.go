// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package bootstrap

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"go.uber.org/zap"

	"github.com/Azure/aks-secure-tls-bootstrap/client/pkg/datamodel"
	"github.com/Azure/aks-secure-tls-bootstrap/client/pkg/testutil"
)

const (
	defaultTestAPIServerFQDN  = "controlplane.azmk8s.io"
	defaultTestKubeconfigPath = "path/to/kubeconfig"
)

var (
	testLogger     *zap.Logger
	defaultTestCfg *Config
)

func TestBootstrap(t *testing.T) {
	testLogger, _ = zap.NewDevelopment()
	RegisterFailHandler(Fail)
	RunSpecs(t, "bootstrap suite")
}

var _ = BeforeSuite(func() {
	clusterCACertPEM, _, err := testutil.GenerateCertPEMWithExpiration("hcp", "aks", time.Now().Add(time.Hour))
	Expect(err).To(BeNil())

	tempDir := GinkgoT().TempDir()
	mockClusterCAFilePath := filepath.Join(tempDir, "ca.crt")
	err = os.WriteFile(mockClusterCAFilePath, clusterCACertPEM, os.ModePerm)
	Expect(err).To(BeNil())

	mockClientCertPath := filepath.Join(tempDir, "client.crt")
	mockClientKeyPath := filepath.Join(tempDir, "client.key")

	defaultTestCfg = &Config{
		NextProto:         "bootstrap",
		ClusterCAFilePath: mockClusterCAFilePath,
		CertFilePath:      mockClientCertPath,
		KeyFilePath:       mockClientKeyPath,
		APIServerFQDN:     defaultTestAPIServerFQDN,
		KubeconfigPath:    defaultTestKubeconfigPath,
		AzureConfig: &datamodel.AzureConfig{
			ClientID:     "clientId",
			ClientSecret: "clientSecret",
			TenantID:     "tenantId",
		},
	}
})
