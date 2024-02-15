// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package client

import (
	"testing"
	"time"

	"github.com/Azure/aks-secure-tls-bootstrap/client/pkg/testutil"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"go.uber.org/zap"
)

var (
	logger           *zap.Logger
	clusterCACertPEM []byte
)

func TestTLSBootstrapClient(t *testing.T) {
	logger, _ = zap.NewDevelopment()
	RegisterFailHandler(Fail)
	RunSpecs(t, "client suite")
}

var _ = BeforeSuite(func() {
	var err error
	clusterCACertPEM, _, err = testutil.GenerateCertPEMWithExpiration("hcp", "aks", time.Now().Add(time.Hour))
	Expect(err).To(BeNil())
})
