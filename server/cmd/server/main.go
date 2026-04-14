// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/Azure/aks-secure-tls-bootstrap/server/internal/server"
	"go.uber.org/zap"
)

const (
	defaultPort = 8080
)

func main() {
	os.Exit(run())
}

func run() int {
	var port int
	flag.IntVar(&port, "port", defaultPort, "port to listen on")
	flag.Parse()

	logger, err := zap.NewProduction()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create logger: %v\n", err)
		return 1
	}
	defer logger.Sync() //nolint:errcheck

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	s := server.New(logger, port)
	if err := s.Start(ctx); err != nil {
		logger.Error("server error", zap.Error(err))
		return 1
	}

	return 0
}
