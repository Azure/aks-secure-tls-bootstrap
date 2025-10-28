// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package log

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

func TestLeveledLoggerShim(t *testing.T) {
	cases := []struct {
		name                     string
		logFunc                  func(*LeveledLoggerShim)
		expectedStdoutSubstrs    []string
		notExpectedStdoutSubstrs []string
	}{
		{
			name: "should correctly shim into a zap.Logger",
			logFunc: func(shim *LeveledLoggerShim) {
				shim.Info("info", "field", "value")
				shim.Warn("warn", "field", "value")
				shim.Error("error", "field", "value")
				shim.Debug("debug", "field", "value")
			},
			notExpectedStdoutSubstrs: []string{"leveled_logger_fields"},
		},
		{
			name: "unexpected number of keys and values are specified",
			logFunc: func(shim *LeveledLoggerShim) {
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

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			shim := &LeveledLoggerShim{
				logger: logger,
			}
			c.logFunc(shim)

			err := bufWriter.Flush()
			assert.NoError(t, err)

			out := buf.String()
			assert.NotEmpty(t, out)

			for _, substr := range c.expectedStdoutSubstrs {
				assert.Contains(t, out, substr)
			}
			for _, substr := range c.notExpectedStdoutSubstrs {
				assert.NotContains(t, out, substr)
			}
		})
	}
}
