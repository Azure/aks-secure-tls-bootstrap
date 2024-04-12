// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package client

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Azure/aks-secure-tls-bootstrap/client/pkg/testutil"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"go.uber.org/zap"
)

var (
	logger                *zap.Logger
	mockClusterCAFilePath string
)

func TestTLSBootstrapClient(t *testing.T) {
	logger, _ = zap.NewDevelopment()
	RegisterFailHandler(Fail)
	RunSpecs(t, "client suite")
}

var _ = BeforeSuite(func() {
	clusterCACertPEM, _, err := testutil.GenerateCertPEMWithExpiration("hcp", "aks", time.Now().Add(time.Hour))
	Expect(err).To(BeNil())

	tempDir := GinkgoT().TempDir()
	mockClusterCAFilePath = filepath.Join(tempDir, "ca.crt")
	err = os.WriteFile(mockClusterCAFilePath, clusterCACertPEM, os.ModePerm)
	Expect(err).To(BeNil())
})
