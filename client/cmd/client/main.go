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
	"github.com/Azure/aks-secure-tls-bootstrap/client/internal/kubeconfig"
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
	flag.StringVar(&config.CustomClientID, "custom-client-id", "", "client ID of the user-assigned managed identity to use when requesting a token from IMDS - if not specified the inferred kubelet identity will be used")
	flag.StringVar(&config.AADResource, "aad-resource", "", "resource (audience) used to request JWT tokens from AAD for authentication")
	flag.StringVar(&config.NextProto, "next-proto", "", "ALPN next proto value")
	flag.StringVar(&config.KubeconfigPath, "kubeconfig", "", "path to the kubeconfig - if this file does not exist, the generated kubeconfig will be placed there - this should be the same as the --kubeconfig passed to the kubelet")
	flag.StringVar(&config.ClusterCAFilePath, "cluster-ca-file", "", "path to the cluster CA file")
	flag.StringVar(&config.CertDir, "cert-dir", "", "the directory where kubelet's new client certificate/key pair will be stored - this should be the same as the --cert-dir passed to the kubelet")
	flag.BoolVar(&config.InsecureSkipTLSVerify, "insecure-skip-tls-verify", false, "skip TLS verification when connecting to the control plane")
	flag.BoolVar(&config.EnsureAuthorizedClient, "ensure-authorized", false, "ensure the specified kubeconfig contains an authorized clientset before bootstrapping")
	flag.DurationVar(&config.Deadline, "deadline", 3*time.Minute, "the deadline within which bootstrapping must succeed")
	flag.Parse()
}

func main() {
	if configFile != "" {
		if err := config.LoadFromFile(configFile); err != nil {
			fmt.Printf("unable to load configuration file: %s\n", err)
			os.Exit(1)
		}
	}
	if err := config.Validate(); err != nil {
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

	var endTime time.Time
	result := &bootstrap.Result{
		Status: bootstrap.StatusSuccess,
	}

	startTime := time.Now()
	deadline := startTime.Add(config.Deadline)
	bootstrapCtx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	logger.Info("set bootstrap deadline", zap.Time("deadline", deadline))

	kubeconfigPath := config.KubeconfigPath
	err = kubeconfig.NewValidator().Validate(bootstrapCtx, kubeconfigPath, config.EnsureAuthorizedClient)
	if err == nil {
		logger.Info("existing kubeconfig is valid, will not bootstrap a new kubelet client credential", zap.String("kubeconfig", kubeconfigPath))
		endTime = time.Now()
		emitGuestAgentEvent(logger, startTime, endTime, result)
		return 0
	}
	logger.Info("failed to validate existing kubeconfig, will bootstrap a new kubelet client credential", zap.String("kubeconfig", kubeconfigPath), zap.Error(err))

	err, errLog, traces := bootstrap.Bootstrap(bootstrapCtx, config)
	endTime = time.Now()
	result.Errors = errLog
	result.Traces = traces.GetLastNTraces(5) // only keep the last 5 traces to avoid truncating guest agent event data
	result.TraceSummary = traces.GetTraceSummary()

	var exitCode int
	if err != nil {
		result.Status = bootstrap.StatusFailure
		switch {
		case errors.Is(err, context.Canceled):
			logger.Error("context was cancelled before bootstrapping could complete")
		case errors.Is(err, context.DeadlineExceeded):
			logger.Error(
				"failed to successfully bootstrap before the specified deadline",
				zap.Error(errors.Unwrap(err)),
				zap.Time("deadline", deadline),
				zap.Duration("deadlineDuration", config.Deadline),
			)
		default:
			logger.Error("failed to bootstrap", zap.Error(errors.Unwrap(err)))
		}
		result.FinalError = errors.Unwrap(err).Error()
		exitCode = 1
	}

	emitGuestAgentEvent(logger, startTime, endTime, result)
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
