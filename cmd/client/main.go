// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/Azure/aks-tls-bootstrap-client/pkg/client"
	"github.com/spf13/cobra"
)

const (
	flagCustomClientID = "custom-client-id"
	flagNextProto      = "next-proto"
	flagAADResource    = "aad-resource"
	flagVerbose        = "verbose"
)

var rootCmd = &cobra.Command{
	Use:   "tls-bootstrap-client",
	Short: "tls-bootstrap-client - secure TLS bootstrap client used to generated dynamic TLS bootstrap tokens via the AKS secure TLS bootstrapping protocol",
}

func main() {
	rootCmd.AddCommand(createBootstrapCommand())
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func createBootstrapCommand() *cobra.Command {
	var opts client.SecureTLSBootstrapClientOpts

	cmd := &cobra.Command{
		Use:   "bootstrap",
		Short: "generate a secure TLS bootstrap token to securely join an AKS cluster",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := opts.Validate(); err != nil {
				return err
			}

			logger, err := client.GetLogger(opts.Verbose)
			if err != nil {
				return err
			}
			defer client.FlushBufferOnExit(logger)

			bootstrapClient := client.NewTLSBootstrapClient(logger, opts)

			ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer cancel()

			cred, err := bootstrapClient.GetCredential(ctx)
			if err != nil {
				return err
			}

			//nolint:forbidigo // kubelet needs the credential printed to stdout
			fmt.Println(cred)
			return nil
		},
	}

	cmd.Flags().StringVar(&opts.CustomClientID, flagCustomClientID, "", "The custome user-specified client ID for the assigned identity to use.")
	cmd.Flags().StringVar(&opts.AADResource, flagAADResource, "", "The resource (audience) used to request JWT tokens from AAD for authentication")
	cmd.Flags().StringVar(&opts.NextProto, flagNextProto, "", "The ALPN Next Protocol value to send within requests to the bootstrap server.")
	cmd.Flags().BoolVar(&opts.Verbose, flagVerbose, false, "Enable verbose logging.")
	return cmd
}
