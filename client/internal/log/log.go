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

type flushFunc func(logger *zap.Logger)

func NewProductionLogger(logFile string, verbose bool) (*zap.Logger, flushFunc, error) {
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

	flush := func(logger *zap.Logger) {
		// per guidance from: https://github.com/uber-go/zap/issues/328
		_ = logger.Sync()
	}

	return zap.New(zapcore.NewTee(cores...)), flush, nil
}

func WithLogger(ctx context.Context, logger *zap.Logger) context.Context {
	return context.WithValue(ctx, contextKey{}, logger)
}

func MustGetLogger(ctx context.Context) *zap.Logger {
	v := ctx.Value(contextKey{})
	if v == nil {
		panic("logger not found on context")
	}
	logger, ok := v.(*zap.Logger)
	if !ok {
		panic("logger not found on context")
	}
	return logger
}

func NewTestContext() context.Context {
	logger, _ := zap.NewDevelopment()
	return WithLogger(context.Background(), logger)
}
