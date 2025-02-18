// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package http

import (
	"bufio"
	"bytes"
	"io"
	"net/url"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"go.uber.org/zap"
)

type customWriter struct {
	io.Writer
}

func (cw customWriter) Close() error {
	return nil
}
func (cw customWriter) Sync() error {
	return nil
}

var _ = Describe("leveledLoggerShim", Ordered, func() {
	var (
		buf       bytes.Buffer
		bufWriter *bufio.Writer
		logger    *zap.Logger
	)

	BeforeAll(func() {
		bufWriter = bufio.NewWriter(&buf)

		config := zap.NewDevelopmentConfig()
		config.EncoderConfig.FunctionKey = "function"

		err := zap.RegisterSink("custom", func(u *url.URL) (zap.Sink, error) {
			return &customWriter{bufWriter}, nil
		})
		Expect(err).To(BeNil())

		config.OutputPaths = []string{"custom:test"}

		logger, err = config.Build()
		Expect(err).To(BeNil())
	})

	It("should correctly shim into a zap.Logger", func() {
		shim := &leveledLoggerShim{
			logger: logger,
		}

		shim.Info("info", "field", "value")
		shim.Warn("warn", "field", "value")
		shim.Error("error", "field", "value")
		shim.Debug("debug", "field", "value")

		err := bufWriter.Flush()
		Expect(err).To(BeNil())

		out := buf.String()
		Expect(out).ToNot(BeEmpty())
		Expect(out).ToNot(ContainSubstring("leveled_logger_fields"))
	})

	When("unexpected number of keys and values are specified", func() {
		It("should inject all keys and values as a single leveled_logger_fields field", func() {
			shim := &leveledLoggerShim{
				logger: logger,
			}

			shim.Info("info", "field", "value", "otherField")
			shim.Warn("warn", "field", "value", "otherField")
			shim.Error("error", "field", "value", "otherField")
			shim.Debug("debug", "field", "value", "otherValue")

			err := bufWriter.Flush()
			Expect(err).To(BeNil())

			out := buf.String()
			Expect(out).ToNot(BeEmpty())
			Expect(out).To(ContainSubstring("leveled_logger_fields"))
		})
	})
})
