// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/Azure/aks-secure-tls-bootstrap/client/pkg/client"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
	"k8s.io/client-go/tools/clientcmd"
)

const (
	flagLogFile                    = "log-file"
	flagAzureConfigPath            = "azure-config"
	flagClusterCAFilePath          = "cluster-ca-file"
	flagAPIServerFQDN              = "apiserver-fqdn"
	flagCustomClientID             = "custom-client-id"
	flagLogFormat                  = "log-format"
	flagNextProto                  = "next-proto"
	flagAADResource                = "aad-resource"
	flagVerbose                    = "verbose"
	flagKubeconfigPath             = "kubeconfig"
	flagInsecureSkipTLSVerify      = "insecure-skip-tls-verify"
	flagEnsureClientAuthentication = "ensure-client-authentication"
)

var rootCmd = &cobra.Command{
	Use:   "tls-bootstrap-client",
	Short: "tls-bootstrap-client - secure TLS bootstrap client used to generate kubelet client credentials via the AKS secure TLS bootstrapping protocol",
}

func main() {
	rootCmd.AddCommand(createBootstrapCommand())
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func createBootstrapCommand() *cobra.Command {
	var (
		opts              = &client.GetKubeletClientCredentialOpts{}
		azureConfigPath   string
		clusterCAFilePath string
		logFile           string
		format            string
		verbose           bool
	)

	cmd := &cobra.Command{
		Use:   "bootstrap",
		Short: "generate a secure TLS bootstrap token to securely join an AKS cluster",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := opts.ValidateAndSet(azureConfigPath, clusterCAFilePath); err != nil {
				return fmt.Errorf("validating and setting opts for kubelet client credential generation: %w", err)
			}

			logger, err := getLoggerForCmd(logFile, format, verbose)
			if err != nil {
				return err
			}
			defer flush(logger)

			bootstrapClient, err := client.NewSecureTLSBootstrapClient(logger)
			if err != nil {
				return err
			}

			ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer cancel()

			kubeconfigData, err := bootstrapClient.GetKubeletClientCredential(ctx, opts)
			if err != nil {
				return err
			}

			// kubeconfigData will be nil when bootstrapping is skipped
			if kubeconfigData != nil {
				logger.Info("writing generated kubeconfig data to disk", zap.String("kubeconfig", opts.KubeconfigPath))
				return clientcmd.WriteToFile(*kubeconfigData, opts.KubeconfigPath)
			} else {
				logger.Info("existing kubeconfig is already valid, no new kubeconfig data to write")
			}

			return nil
		},
	}

	cmd.Flags().BoolVar(&verbose, flagVerbose, false, "Enable verbose logging.")
	cmd.Flags().StringVar(&azureConfigPath, flagAzureConfigPath, "", "Path to the azure config file.")
	cmd.Flags().StringVar(&clusterCAFilePath, flagClusterCAFilePath, "", "Path to the cluster CA file.")
	cmd.Flags().StringVar(&logFile, flagLogFile, "", "Path to the file where logs will be written.")
	cmd.Flags().StringVar(&format, flagLogFormat, "json", "Log format: json or console.")
	cmd.Flags().BoolVar(&opts.InsecureSkipTLSVerify, flagInsecureSkipTLSVerify, false, "Skip TLS verification when connecting to the API server FQDN.")
	cmd.Flags().BoolVar(&opts.EnsureClientAuthentication, flagEnsureClientAuthentication, false, "Ensure kubernetes client authentication before generating a new certificate.")
	cmd.Flags().StringVar(&opts.APIServerFQDN, flagAPIServerFQDN, "", "FQDN of the apiserver.")
	cmd.Flags().StringVar(&opts.CustomClientID, flagCustomClientID, "", "Client ID of the user-assigned managed identity to use. Will default to kubelet identity on MSI-enabled clusters if this is not specified.")
	cmd.Flags().StringVar(&opts.AADResource, flagAADResource, "", "Resource (audience) used to request JWT tokens from AAD for authentication.")
	cmd.Flags().StringVar(&opts.NextProto, flagNextProto, "", "ALPN Next Protocol value to send within requests to the bootstrap server.")
	cmd.Flags().StringVar(&opts.KubeconfigPath, flagKubeconfigPath, "", "Path to the kubeconfig file containing the generated kubelet client certificate.")
	return cmd
}

func getLoggerForCmd(logFile, format string, verbose bool) (*zap.Logger, error) {
	cfg := zap.NewProductionConfig()
	if logFile != "" {
		cfg.OutputPaths = append(cfg.OutputPaths, logFile)
	}
	// Production config defaults to INFO level
	if verbose {
		cfg.Level = zap.NewAtomicLevelAt(zap.DebugLevel)
	}
	// Production config defaults to JSON encoding
	if strings.EqualFold(format, "console") {
		cfg.Encoding = "console"
	}

	logger, err := cfg.Build()
	if err != nil {
		return nil, err
	}

	return logger, nil
}

func flush(logger *zap.Logger) {
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
