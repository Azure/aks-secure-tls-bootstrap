// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package client

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

func setupLogsCapture() (*zap.Logger, *observer.ObservedLogs) {
	core, logs := observer.New(zap.InfoLevel)
	return zap.New(core), logs
}

var _ = Describe("Log tests", func() {
	Context("getLogger tests", func() {
		When("format is json", func() {
			It("should return a new logger with format set to JSON", func() {
				var (
					format = "json"
					debug  = false
				)
				logger := GetLogger(format, debug)
				Expect(logger).ToNot(BeNil())
				Expect(logger.Core().Enabled(zap.InfoLevel)).To(BeTrue())
				Expect(logger.Core().Enabled(zap.DebugLevel)).To(BeFalse())
			})
		})

		When("debug is true", func() {
			It("should return a new logger using the debug level", func() {
				var (
					format = "json"
					debug  = true
				)
				logger := GetLogger(format, debug)
				Expect(logger).ToNot(BeNil())
				Expect(logger.Core().Enabled(zap.InfoLevel)).To(BeTrue())
				Expect(logger.Core().Enabled(zap.DebugLevel)).To(BeTrue())
			})
		})

		When("using a capture logger", func() {
			It("should be able to capture the string in the log", func() {
				logger, logs := setupLogsCapture()
				logger.Warn("This is the warning")
				Expect(logs.Len()).To(Equal(1))
				Expect(logs.All()[0].Message).To(Equal("This is the warning"))
			})
		})
	})
})
