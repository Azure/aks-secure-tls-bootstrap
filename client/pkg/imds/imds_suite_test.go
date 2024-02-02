// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package imds

import (
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"go.uber.org/zap"
)

var logger *zap.Logger

func TestIMDS(t *testing.T) {
	logger, _ = zap.NewDevelopment()
	RegisterFailHandler(Fail)
	RunSpecs(t, "imds suite")
}
