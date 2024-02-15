// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package aad

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"go.uber.org/zap"
)

var logger *zap.Logger

func TestAAD(t *testing.T) {
	logger, _ = zap.NewDevelopment()
	RegisterFailHandler(Fail)
	RunSpecs(t, "aad suite")
}
