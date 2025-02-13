// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/Azure/aks-secure-tls-bootstrap/client/pkg/bootstrap"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"k8s.io/client-go/tools/clientcmd"
)

var (
	bootstrapConfig bootstrap.Config
	configFile      string
	logFile         string
	format          string
	verbose         bool
)

func init() {
	flag.StringVar(&configFile, "config-file", "", "path to the configuration file, settings in this file will take priority over command line arguments")
	flag.StringVar(&logFile, "log-file", "", "path to a file where logs will be written")
	flag.StringVar(&format, "format", "json", "log format (json or console)")
	flag.BoolVar(&verbose, "verbose", false, "enable verbose log output")
	flag.StringVar(&bootstrapConfig.AzureConfigPath, "azure-config", "", "path to the azure config file")
	flag.StringVar(&bootstrapConfig.APIServerFQDN, "apiserver-fqdn", "", "FQDN of the apiserver")
	flag.StringVar(&bootstrapConfig.CustomClientID, "custom-client-id", "", "client ID of the user-assigned managed identity to use when requesting a token from IMDS - if not specified the kubelet identity will be used")
	flag.StringVar(&bootstrapConfig.AADResource, "aad-resource", "", "resource (audience) used to request JWT tokens from AAD for authentication")
	flag.StringVar(&bootstrapConfig.NextProto, "next-proto", "", "ALPN next proto value")
	flag.StringVar(&bootstrapConfig.KubeconfigPath, "kubeconfig", "", "path to the kubeconfig - if this file does not exist, the generated kubeconfig will be placed there")
	flag.StringVar(&bootstrapConfig.ClusterCAFilePath, "cluster-ca-file", "", "path to the cluster CA file")
	flag.StringVar(&bootstrapConfig.CertFilePath, "cert-file", "", "path to the file which will contain the PEM-encoded client certificate, referenced by the generated kubeconfig")
	flag.StringVar(&bootstrapConfig.KeyFilePath, "key-file", "", "path to the file which will contain the PEM-encoded client key, referenced by the generated kubeconfig.")
	flag.BoolVar(&bootstrapConfig.InsecureSkipTLSVerify, "insecure-skip-tls-verify", false, "skip TLS verification when connecting to the control plane")
	flag.BoolVar(&bootstrapConfig.EnsureAuthorizedClient, "ensure-authorized", false, "ensure the specified kubeconfig contains an authorized clientset before bootstrapping")
	flag.Parse()
}

func main() {
	logger, err := constructLogger(logFile, format, verbose)
	if err != nil {
		fmt.Printf("unable to construct zap logger: %s\n", err)
		os.Exit(1)
	}
	// defer calls are not executed on os.Exit
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	exitCode := run(ctx, logger)
	cancel()
	flush(logger)
	os.Exit(exitCode)
}

func run(ctx context.Context, logger *zap.Logger) int {
	if configFile != "" {
		if err := bootstrapConfig.LoadFromFile(configFile); err != nil {
			logger.Error("error loading configuration file", zap.Error(err))
		}
	}
	client, err := bootstrap.NewClient(logger)
	if err != nil {
		logger.Error("error constructing bootstrap client", zap.Error(err))
		return 1
	}
	kubeconfigData, err := client.GetKubeletClientCredential(ctx, &bootstrapConfig)
	if err != nil {
		logger.Error("error generating kubelet client credential", zap.Error(err))
		return 1
	}
	if err := clientcmd.WriteToFile(*kubeconfigData, bootstrapConfig.KubeconfigPath); err != nil {
		logger.Error("error writing generated kubeconfig to disk", zap.Error(err))
		return 1
	}
	return 0
}

func constructLogger(logFile, format string, verbose bool) (*zap.Logger, error) {
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
