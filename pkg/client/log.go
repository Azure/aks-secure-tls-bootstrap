// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package client

import (
	"go.uber.org/zap"
)

func GetLogger(format string, debug bool) (*zap.Logger, error) {
	var logLevel zap.AtomicLevel
	if debug {
		logLevel = zap.NewAtomicLevelAt(zap.DebugLevel)
	} else {
		logLevel = zap.NewAtomicLevelAt(zap.InfoLevel)
	}

	cfg := zap.Config{
		Encoding: format,
		Level:    logLevel,
	}

	logger, err := cfg.Build()
	if err != nil {
		return nil, err
	}

	logger.Info("Logger initialized")

	return logger, nil
}

func FlushBufferOnExit(logger *zap.Logger) {
	if err := logger.Sync(); err != nil {
		logger.Error("Error during logger synchronization", zap.Error(err))
	}
}
