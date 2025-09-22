// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package log

import (
	"github.com/hashicorp/go-retryablehttp"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var _ retryablehttp.LeveledLogger = (*LeveledLoggerShim)(nil)

// LeveledLoggerShim provides an implementation of retryablehttp.LeveledLogger, shimming into a zap.Logger.
type LeveledLoggerShim struct {
	logger *zap.Logger
}

func NewLeveledLoggerShim(logger *zap.Logger) *LeveledLoggerShim {
	return &LeveledLoggerShim{
		logger: logger,
	}
}

func (l *LeveledLoggerShim) Debug(msg string, keysAndValues ...any) {
	l.logger.Debug(msg, getZapFields(keysAndValues)...)
}

func (l *LeveledLoggerShim) Error(msg string, keysAndValues ...any) {
	l.logger.Error(msg, getZapFields(keysAndValues)...)
}

func (l *LeveledLoggerShim) Info(msg string, keysAndValues ...any) {
	l.logger.Info(msg, getZapFields(keysAndValues)...)
}

func (l *LeveledLoggerShim) Warn(msg string, keysAndValues ...any) {
	l.logger.Warn(msg, getZapFields(keysAndValues)...)
}

func getZapFields(keysAndValues []any) []zap.Field {
	var fields []zap.Field
	failed := len(keysAndValues)%2 != 0
	for i := 0; i < len(keysAndValues)-1 && !failed; i += 2 {
		key, ok := keysAndValues[i].(string)
		if !ok || i+1 >= len(keysAndValues) {
			failed = true
			break
		}
		fields = append(fields, zap.Any(key, keysAndValues[i+1]))
	}
	if failed {
		fields = []zapcore.Field{
			zap.Any("leveled_logger_fields", keysAndValues),
		}
	}
	return fields
}
