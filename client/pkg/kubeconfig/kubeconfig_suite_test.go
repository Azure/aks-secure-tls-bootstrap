// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package kubeconfig

import (
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestKubeconfig(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "kubeconfig suite")
}
