// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package client

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"go.uber.org/zap"
)

var _ = Describe("Log tests", func() {
	Context("getLogger tests", func() {
		When("verbose is false", func() {
			It("should return a new logger using the info level", func() {
				verbose := false
				logger, err := GetLogger(verbose)
				Expect(err).To(BeNil())
				Expect(logger).ToNot(BeNil())
				Expect(logger.Core().Enabled(zap.InfoLevel)).To(BeTrue())
				Expect(logger.Core().Enabled(zap.DebugLevel)).To(BeFalse())
			})
		})

		When("verbose is true", func() {
			It("should return a new logger using the debug level", func() {
				verbose := true
				logger, err := GetLogger(verbose)
				Expect(err).To(BeNil())
				Expect(logger).ToNot(BeNil())
				Expect(logger.Core().Enabled(zap.InfoLevel)).To(BeTrue())
				Expect(logger.Core().Enabled(zap.DebugLevel)).To(BeTrue())
			})
		})
	})
})
