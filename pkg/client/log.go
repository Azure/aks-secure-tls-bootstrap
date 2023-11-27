// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package client

import (
	"errors"
	"syscall"

	"go.uber.org/zap"
)

func GetLogger(verbose bool) (*zap.Logger, error) {
	cfg := zap.NewProductionConfig()
	cfg.OutputPaths = []string{"stdout"}

	if verbose {
		cfg.Level = zap.NewAtomicLevelAt(zap.DebugLevel)
	}

	logger, err := cfg.Build()
	if err != nil {
		return nil, err
	}

	logger.Info("zap logger initialized")
	return logger, nil
}

func FlushBufferOnExit(logger *zap.Logger) {
	if err := logger.Sync(); err != nil && !errors.Is(err, syscall.ENOTTY) {
		logger.Error("error during zap logger synchronization", zap.Error(err))
	}
}
