// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package client

import (
	"errors"
	"syscall"

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
	syncErr := logger.Sync()
	if syncErr == nil {
		return
	}

	switch {
	case errors.Is(syncErr, syscall.ENOTTY):
		// This is a known issue with Zap when redirecting stdout/stderr to a console
		// https://github.com/uber-go/zap/issues/880#issuecomment-1181854418
		return
	default:
		logger.Error("Error during logger sync", zap.Error(syncErr))
	}
}
