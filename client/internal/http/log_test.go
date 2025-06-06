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
	var (
		buf       bytes.Buffer
		bufWriter *bufio.Writer
		logger    *zap.Logger
	)

	bufWriter = bufio.NewWriter(&buf)

	config := zap.NewDevelopmentConfig()
	config.EncoderConfig.FunctionKey = "function"

	err := zap.RegisterSink("custom", func(u *url.URL) (zap.Sink, error) {
		return &customWriter{bufWriter}, nil
	})
	assert.NoError(t, err)

	config.OutputPaths = []string{"custom:test"}

	logger, err = config.Build()
	assert.NoError(t, err)

	tests := []struct {
		name    string
		logFunc func()
	}{
		{
			name: "should correctly shim into a zap.Logger",
			logFunc: func() {
				shim := &leveledLoggerShim{
					logger: logger,
				}

				shim.Info("info", "field", "value")
				shim.Warn("warn", "field", "value")
				shim.Error("error", "field", "value")
				shim.Debug("debug", "field", "value")
			},
		},
		{
			name: "unexpected number of keys and values are specified",
			logFunc: func() {
				shim := &leveledLoggerShim{
					logger: logger,
				}

				shim.Info("info", "field", "value", "otherField")
				shim.Warn("warn", "field", "value", "otherField")
				shim.Error("error", "field", "value", "otherField")
				shim.Debug("debug", "field", "value", "otherValue")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.logFunc()

			err := bufWriter.Flush()
			assert.NoError(t, err)

			out := buf.String()
			assert.NotEmpty(t, out)
			if tt.name == "unexpected number of keys and values are specified" {
				assert.Contains(t, out, "leveled_logger_fields")
			} else {
				assert.NotContains(t, out, "leveled_logger_fields")
			}
		})
	}
}
