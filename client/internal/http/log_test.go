// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package http

import (
	"bufio"
	"bytes"
	"io"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
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

func TestHttpLog(t *testing.T) {
	tests := []struct {
		name                     string
		logFunc                  func(*leveledLoggerShim)
		expectedStdoutSubstrs    []string
		notExpectedStdoutSubstrs []string
	}{
		{
			name: "should correctly shim into a zap.Logger",
			logFunc: func(shim *leveledLoggerShim) {
				shim.Info("info", "field", "value")
				shim.Warn("warn", "field", "value")
				shim.Error("error", "field", "value")
				shim.Debug("debug", "field", "value")
			},
			notExpectedStdoutSubstrs: []string{"leveled_logger_fields"},
		},
		{
			name: "unexpected number of keys and values are specified",
			logFunc: func(shim *leveledLoggerShim) {
				shim.Info("info", "field", "value", "otherField")
				shim.Warn("warn", "field", "value", "otherField")
				shim.Error("error", "field", "value", "otherField")
				shim.Debug("debug", "field", "value", "otherValue")
			},
			expectedStdoutSubstrs: []string{"leveled_logger_fields"},
		},
	}

	var (
		buf       bytes.Buffer
		bufWriter *bufio.Writer
	)

	bufWriter = bufio.NewWriter(&buf)

	config := zap.NewDevelopmentConfig()
	config.EncoderConfig.FunctionKey = "function"

	err := zap.RegisterSink("custom", func(u *url.URL) (zap.Sink, error) {
		return &customWriter{bufWriter}, nil
	})
	assert.NoError(t, err)

	config.OutputPaths = []string{"custom:test"}

	logger, err := config.Build()
	assert.NoError(t, err)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			shim := &leveledLoggerShim{
				logger: logger,
			}
			tt.logFunc(shim)

			err := bufWriter.Flush()
			assert.NoError(t, err)

			out := buf.String()
			assert.NotEmpty(t, out)

			for _, substr := range tt.expectedStdoutSubstrs {
				assert.Contains(t, out, substr)
			}

			for _, substr := range tt.notExpectedStdoutSubstrs {
				assert.NotContains(t, out, substr)
			}
		})
	}
}
