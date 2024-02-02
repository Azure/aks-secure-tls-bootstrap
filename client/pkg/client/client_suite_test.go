// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package client

import (
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"go.uber.org/zap"
)

var logger *zap.Logger

func TestTLSBootstrapClient(t *testing.T) {
	logger, _ = zap.NewDevelopment()
	RegisterFailHandler(Fail)
	RunSpecs(t, "client suite")
}
