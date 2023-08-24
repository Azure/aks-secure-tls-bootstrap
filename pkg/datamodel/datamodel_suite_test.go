// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package datamodel

import (
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestTLSBootstrapClient(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "datamodel suite")
}
