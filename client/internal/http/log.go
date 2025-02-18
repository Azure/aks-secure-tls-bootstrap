package http

import (
	"github.com/hashicorp/go-retryablehttp"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var _ retryablehttp.LeveledLogger = (*leveledLoggerShim)(nil)

// leveledLoggerShim provides an implementation of retryablehttp.LeveledLogger, shimming into a zap.Logger.
type leveledLoggerShim struct {
	logger *zap.Logger
}

func (l *leveledLoggerShim) Debug(msg string, keysAndValues ...interface{}) {
	l.logger.Debug(msg, getZapFields(keysAndValues)...)
}

func (l *leveledLoggerShim) Error(msg string, keysAndValues ...interface{}) {
	l.logger.Error(msg, getZapFields(keysAndValues)...)
}

func (l *leveledLoggerShim) Info(msg string, keysAndValues ...interface{}) {
	l.logger.Info(msg, getZapFields(keysAndValues)...)
}

func (l *leveledLoggerShim) Warn(msg string, keysAndValues ...interface{}) {
	l.logger.Warn(msg, getZapFields(keysAndValues)...)
}

func getZapFields(keysAndValues []interface{}) []zap.Field {
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
