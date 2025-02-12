// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/Azure/aks-secure-tls-bootstrap/client/pkg/bootstrap"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"k8s.io/client-go/tools/clientcmd"
)

const (
	flagLogFile                = "log-file"
	flagAzureConfigPath        = "azure-config"
	flagClusterCAFilePath      = "cluster-ca-file"
	flagAPIServerFQDN          = "apiserver-fqdn"
	flagCustomClientID         = "custom-client-id"
	flagLogFormat              = "log-format"
	flagNextProto              = "next-proto"
	flagAADResource            = "aad-resource"
	flagVerbose                = "verbose"
	flagKubeconfigPath         = "kubeconfig"
	flagCertFilePath           = "cert-file"
	flagKeyFilePath            = "key-file"
	flagInsecureSkipTLSVerify  = "insecure-skip-tls-verify"
	flagEnsureAuthorizedClient = "ensure-authorized"
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
		cfg             bootstrap.Config
		azureConfigPath string
		logFile         string
		format          string
		verbose         bool
	)

	cmd := &cobra.Command{
		Use:   "bootstrap",
		Short: "bootstrap a kubelet client credential",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := cfg.ValidateAndSet(azureConfigPath); err != nil {
				return fmt.Errorf("validating and setting cfg for kubelet client credential generation: %w", err)
			}

			logger, err := getLogger(logFile, format, verbose)
			if err != nil {
				return err
			}
			defer flush(logger)

			bootstrapClient, err := bootstrap.NewClient(logger)
			if err != nil {
				return err
			}

			ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer cancel()

			kubeconfigData, err := bootstrapClient.GetKubeletClientCredential(ctx, &cfg)
			if err != nil {
				return err
			}

			// kubeconfigData will be nil when bootstrapping is skipped
			if kubeconfigData == nil {
				logger.Info("existing kubeconfig is already valid, no new kubeconfig data to write")
				return nil
			}

			logger.Info("writing generated kubeconfig data to disk", zap.String("kubeconfig", cfg.KubeconfigPath))
			return clientcmd.WriteToFile(*kubeconfigData, cfg.KubeconfigPath)
		},
	}

	cmd.Flags().BoolVar(&verbose, flagVerbose, false, "Enable verbose logging.")
	cmd.Flags().StringVar(&azureConfigPath, flagAzureConfigPath, "", "Path to the azure config file.")
	cmd.Flags().StringVar(&logFile, flagLogFile, "", "Path to the file where logs will be written.")
	cmd.Flags().StringVar(&format, flagLogFormat, "json", "Log format: json or console.")
	cmd.Flags().BoolVar(&cfg.InsecureSkipTLSVerify, flagInsecureSkipTLSVerify, false, "Skip TLS verification when connecting to the API server FQDN.")
	cmd.Flags().BoolVar(&cfg.EnsureAuthorizedClient, flagEnsureAuthorizedClient, false, "Ensure the specified kubeconfig contains an authorized clientset before bootstrapping.")
	cmd.Flags().StringVar(&cfg.APIServerFQDN, flagAPIServerFQDN, "", "FQDN of the apiserver.")
	cmd.Flags().StringVar(&cfg.CustomClientID, flagCustomClientID, "", "Client ID of the user-assigned managed identity to use. Will default to kubelet identity on MSI-enabled clusters if this is not specified.")
	cmd.Flags().StringVar(&cfg.AADResource, flagAADResource, "", "Resource (audience) used to request JWT tokens from AAD for authentication.")
	cmd.Flags().StringVar(&cfg.NextProto, flagNextProto, "", "ALPN Next Protocol value to send within requests to the bootstrap server.")
	cmd.Flags().StringVar(&cfg.KubeconfigPath, flagKubeconfigPath, "", "Path to the kubeconfig file containing the generated kubelet client certificate.")
	cmd.Flags().StringVar(&cfg.ClusterCAFilePath, flagClusterCAFilePath, "", "Path to the cluster CA file.")
	cmd.Flags().StringVar(&cfg.CertFilePath, flagCertFilePath, "", "Path to the file which will contain the PEM-encoded client certificate, referenced by the generated kubeconfig.")
	cmd.Flags().StringVar(&cfg.KeyFilePath, flagKeyFilePath, "", "Path to the file which will contain the PEM-encoded client key, referenced by the generated kubeconfig.")
	return cmd
}

func getLogger(logFile, format string, verbose bool) (*zap.Logger, error) {
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

	// Use RFC3339 timestamps
	cfg.EncoderConfig.TimeKey = "timestamp"
	cfg.EncoderConfig.EncodeTime = zapcore.TimeEncoderOfLayout(time.RFC3339)

	return cfg.Build()
}

func flush(logger *zap.Logger) {
	// per guidance from: https://github.com/uber-go/zap/issues/328
	_ = logger.Sync()
}
