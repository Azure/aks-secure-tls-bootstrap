// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package log

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

func TestNewProductionLogger(t *testing.T) {
	logFile := filepath.Join(t.TempDir(), "log.json")
	verbose := true

	logger, flush, err := NewProductionLogger(logFile, verbose)
	assert.NoError(t, err)
	assert.NotNil(t, flush)
	assert.NotNil(t, logger)

	logger.Info("log line")
	flush()

	logFileBytes, err := os.ReadFile(logFile)
	assert.NoError(t, err)
	assert.Contains(t, string(logFileBytes), "log line")
}

func TestMustGetLoggerPanics(t *testing.T) {
	defer func() {
		r := recover()
		assert.NotNil(t, r, "expected MustGetLogger to panic")
	}()
	ctx := context.Background()
	_ = MustGetLogger(ctx)
}

func TestContextOperations(t *testing.T) {
	zapLogger, err := zap.NewDevelopment()
	assert.NoError(t, err)
	logger := zapLogger.Sugar()

	ctx := context.Background()

	ctx = WithLogger(ctx, logger)
	assert.NotNil(t, ctx)

	retrievedLogger := MustGetLogger(ctx)
	assert.NotNil(t, retrievedLogger)

	ctx = NewTestContext()
	assert.NotNil(t, ctx)
	testLogger := MustGetLogger(ctx)
	assert.NotNil(t, testLogger)
}
