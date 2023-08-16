// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package client

import (
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
)

var testLogger = logrus.New()

func TestTLSBootstrapClient(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "TLS Bootstrap Client Suite")
}
