// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/Azure/aks-secure-tls-bootstrap/client/internal/bootstrap"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"k8s.io/client-go/tools/clientcmd"
)

var (
	bootstrapConfig bootstrap.Config
	configFile      string
	logFile         string
	verbose         bool
)

func init() {
	flag.StringVar(&configFile, "config-file", "", "path to the configuration file, settings in this file will take priority over command line arguments")
	flag.StringVar(&logFile, "log-file", "", "path to a file where logs will be written, will be created if it does not already exist")
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
	if configFile != "" {
		if err := bootstrapConfig.LoadFromFile(configFile); err != nil {
			fmt.Printf("unable to load configuration file: %s\n", err)
			os.Exit(1)
		}
	}
	if err := bootstrapConfig.Validate(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	logger, err := configureLogging(logFile, verbose)
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

func configureLogging(logFile string, verbose bool) (*zap.Logger, error) {
	if err := os.MkdirAll(filepath.Dir(logFile), 0755); err != nil {
		return nil, fmt.Errorf("failed to create log directory: %w", err)
	}

	logFileHandle, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to open log file: %w", err)
	}

	encoderConfig := zap.NewProductionEncoderConfig()
	encoderConfig.TimeKey = "timestamp"
	encoderConfig.EncodeTime = zapcore.RFC3339NanoTimeEncoder

	fileEncoder := zapcore.NewJSONEncoder(encoderConfig)
	consoleEncoder := zapcore.NewConsoleEncoder(encoderConfig)

	level := zap.InfoLevel
	if verbose {
		level = zap.DebugLevel
	}

	core := zapcore.NewTee(
		zapcore.NewCore(fileEncoder, zapcore.AddSync(logFileHandle), level),
		zapcore.NewCore(consoleEncoder, zapcore.AddSync(os.Stdout), level),
	)
	return zap.New(core), nil
}

func flush(logger *zap.Logger) {
	// per guidance from: https://github.com/uber-go/zap/issues/328
	_ = logger.Sync()
}
