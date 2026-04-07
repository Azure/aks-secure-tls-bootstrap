// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Azure/aks-secure-tls-bootstrap/client/internal/bootstrap"
	"github.com/Azure/aks-secure-tls-bootstrap/client/internal/build"
	"github.com/Azure/aks-secure-tls-bootstrap/client/internal/log"
	"github.com/Azure/aks-secure-tls-bootstrap/client/internal/telemetry"
	"go.uber.org/zap"
)

var config = new(bootstrap.Config)

var (
	configFile string
	logFile    string
	verbose    bool
)

func init() {
	flag.StringVar(&configFile, "config-file", "", "path to the configuration file, settings in this file will take priority over command line arguments")
	flag.StringVar(&logFile, "log-file", "", "path to a file where logs will be written, will be created if it does not already exist")
	flag.BoolVar(&verbose, "verbose", false, "enable verbose log output")

	flag.StringVar(&config.CloudProviderConfigPath, "cloud-provider-config", "", "path to the cloud provider config file")
	flag.StringVar(&config.APIServerFQDN, "apiserver-fqdn", "", "FQDN of the apiserver")
	flag.StringVar(&config.UserAssignedIdentityID, "user-assigned-identity-id", "", "client ID of the user-assigned identity to use when requesting MSI tokens from IMDS - if not specified, the kubelet identity from the cloud provider config will be used")
	flag.StringVar(&config.AADResource, "aad-resource", "", "resource (audience) used to request JWT tokens from AAD for authentication")
	flag.StringVar(&config.NextProto, "next-proto", "", "ALPN next proto value")
	flag.StringVar(&config.KubeconfigPath, "kubeconfig", "", "path to the kubeconfig - if this file does not exist, the generated kubeconfig will be placed there - this should be the same as the --kubeconfig passed to the kubelet")
	flag.StringVar(&config.ClusterCAFilePath, "cluster-ca-file", "", "path to the cluster CA file")
	flag.StringVar(&config.CertDir, "cert-dir", "", "the directory where kubelet's new client certificate/key pair will be stored - this should be the same as the --cert-dir passed to the kubelet")
	flag.StringVar(&config.TLSMinVersion, "tls-min-version", "", "the minimum TLS version used to communicate with control plane")
	flag.BoolVar(&config.InsecureSkipTLSVerify, "insecure-skip-tls-verify", false, "skip TLS verification when connecting to the control plane")
	flag.BoolVar(&config.EnsureAuthorizedClient, "ensure-authorized", false, "ensure the specified kubeconfig contains an authorized clientset before bootstrapping")
	flag.DurationVar(&config.GetAccessTokenTimeout, "get-access-token-timeout", 0, "timeout applied to the get access token RPC")
	flag.DurationVar(&config.GetInstanceDataTimeout, "get-instance-data-timeout", 0, "timeout applied to the get instance data RPC")
	flag.DurationVar(&config.GetNonceTimeout, "get-nonce-timeout", 0, "timeout applied to the get nonce RPC")
	flag.DurationVar(&config.GetAttestedDataTimeout, "get-attested-data-timeout", 0, "timeout applied to the get attested data RPC")
	flag.DurationVar(&config.GetCredentialTimeout, "get-credential-timeout", 0, "timeout applied to the get credential RPC")
	flag.DurationVar(&config.Deadline, "deadline", 0, "the deadline within which bootstrapping must succeed - DEPRECATED, use RPC timeouts instead")

	flag.Usage = func() {
		_, _ = fmt.Fprintf(os.Stderr, "Usage of %s - %s:\n", os.Args[0], build.GetVersion())
		flag.PrintDefaults()
	}

	flag.Parse()
}

func main() {
	if configFile != "" {
		if err := config.LoadFromFile(configFile); err != nil {
			fmt.Printf("unable to load configuration file: %s\n", err)
			os.Exit(1)
		}
	}
	if err := config.DefaultAndValidate(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	// defer calls are not executed on os.Exit
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM, syscall.SIGABRT, syscall.SIGKILL)
	exitCode := run(ctx)
	cancel()
	os.Exit(exitCode)
}

func run(ctx context.Context) int {
	logger, flush, err := log.NewProductionLogger(logFile, verbose)
	if err != nil {
		fmt.Printf("unable to construct zap logger: %s\n", err)
		return 1
	}
	defer flush()

	ctx = log.WithLogger(telemetry.WithTracing(ctx), logger)

	logger.Info("running with config", zap.String("config", config.String()))

	var startTime, endTime time.Time
	result := &bootstrap.Result{
		Status: bootstrap.StatusSuccess,
	}
	defer func() {
		result.Trace = telemetry.GetTrace(ctx)
		emitGuestAgentEvent(logger, startTime, endTime, result)
	}()

	startTime = time.Now()
	err = bootstrap.Bootstrap(ctx, config)
	endTime = time.Now()

	var exitCode int
	if err != nil {
		result.Status = bootstrap.StatusFailure
		switch {
		case errors.Is(err, context.Canceled):
			logger.Error("context was canceled before bootstrapping could complete")
		case errors.Is(err, context.DeadlineExceeded):
			logger.Error(
				"failed to bootstrap due to exceeding context deadline",
				zap.Error(err),
			)
		default:
			logger.Error("failed to bootstrap", zap.Error(err))
		}
		result.FinalError = err.Error()
		exitCode = 1
	}

	return exitCode
}

func emitGuestAgentEvent(logger *zap.Logger, startTime, endTime time.Time, result *bootstrap.Result) {
	result.ElapsedMilliseconds = endTime.Sub(startTime).Milliseconds()
	bootstrapEvent := &bootstrap.Event{
		Start: startTime,
		End:   endTime,
	}
	eventFilePath, err := bootstrapEvent.WriteWithResult(result)
	if err != nil {
		logger.Error("unable to write bootstrap guest agent event to disk", zap.Error(err))
	}
	if eventFilePath == "" {
		logger.Warn("guest agent event path does not exist, no guest agent event telemetry will be written", zap.String("eventMessage", bootstrapEvent.Message))
	} else {
		logger.Info("bootstrapping guest agent event telemetry written to disk", zap.String("path", eventFilePath))
	}
}
