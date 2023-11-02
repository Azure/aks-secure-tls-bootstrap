// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package client

import (
	"go.uber.org/zap"
)

func GetLogger(format string, debug bool) *zap.Logger {
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
		panic("Failed to initialize logger: " + err.Error())
	}
	defer logger.Sync()

	logger.Info("Logger initialized")

	return logger
}
