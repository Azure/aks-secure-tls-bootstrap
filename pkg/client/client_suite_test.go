// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package client

import (
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"go.uber.org/zap"
)

var testLogger *zap.Logger

func TestTLSBootstrapClient(t *testing.T) {
	testLogger, _ = zap.NewProduction()
	defer func() {
		if err := testLogger.Sync(); err != nil {
			testLogger.Error("Error during logger synchronization", zap.Error(err))
		}
	}()
	RegisterFailHandler(Fail)
	RunSpecs(t, "TLS Bootstrap Client Suite")
}
