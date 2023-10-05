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

	"github.com/Azure/aks-tls-bootstrap-client/pkg/client"
)

func main() {
	var (
		clientID    = flag.String("client-id", "", "The client ID for the assigned identity to use.")
		logFormat   = flag.String("log-format", "json", "Log format: json or text, default: json")
		nextProto   = flag.String("next-proto", "", "ALPN Next Protocol value to send.")
		aadResource = flag.String("aad-resource", "", "The resource/audience used to request JWT tokens from AAD")
		debug       = flag.Bool("debug", false, "enable debug logging (WILL LOG AUTHENTICATION DATA)")
	)

	flag.Parse()
	logger := client.GetLogger(*logFormat, *debug)
	bootstrapClient := client.NewTLSBootstrapClient(logger, *clientID, *nextProto, *aadResource)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	token, err := bootstrapClient.GetBootstrapToken(ctx)
	if err != nil {
		logger.Fatalf("Failed to retrieve bootstrap token: %s", err)
	}

	//nolint:forbidigo // kubelet needs the token printed to stdout
	fmt.Println(token)
}
