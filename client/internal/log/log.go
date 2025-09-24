// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package log

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type contextKey struct{}

type flushFunc func()

func NewProductionLogger(logFile string, verbose bool) (*zap.SugaredLogger, flushFunc, error) {
	encoderConfig := zap.NewProductionEncoderConfig()
	encoderConfig.TimeKey = "timestamp"
	encoderConfig.EncodeTime = zapcore.RFC3339NanoTimeEncoder

	level := zap.InfoLevel
	if verbose {
		level = zap.DebugLevel
	}

	cores := []zapcore.Core{
		zapcore.NewCore(
			zapcore.NewConsoleEncoder(encoderConfig),
			zapcore.AddSync(os.Stdout),
			level,
		),
	}

	if logFile != "" {
		if err := os.MkdirAll(filepath.Dir(logFile), 0755); err != nil {
			return nil, nil, fmt.Errorf("failed to create log directory: %w", err)
		}
		logFileHandle, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to open log file: %w", err)
		}
		cores = append(cores, zapcore.NewCore(
			zapcore.NewJSONEncoder(encoderConfig),
			zapcore.AddSync(logFileHandle),
			level,
		))
	}

	logger := zap.New(zapcore.NewTee(cores...)).Sugar()

	flush := func() {
		// per guidance from: https://github.com/uber-go/zap/issues/328
		_ = logger.Sync()
	}

	return logger, flush, nil
}

func WithLogger(ctx context.Context, logger *zap.SugaredLogger) context.Context {
	return context.WithValue(ctx, contextKey{}, logger)
}

func MustGetLogger(ctx context.Context) *zap.SugaredLogger {
	logger, ok := ctx.Value(contextKey{}).(*zap.SugaredLogger)
	if !ok {
		panic("logger not found on context")
	}
	return logger
}

func NewTestContext() context.Context {
	logger, _ := zap.NewDevelopment()
	return WithLogger(context.Background(), logger.Sugar())
}
