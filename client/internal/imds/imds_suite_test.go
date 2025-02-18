// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package imds

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestIMDS(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "imds suite")
}
