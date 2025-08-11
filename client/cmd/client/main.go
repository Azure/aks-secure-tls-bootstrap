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
	"path/filepath"
	"syscall"
	"time"

	"github.com/Azure/aks-secure-tls-bootstrap/client/internal/bootstrap"
	"github.com/Azure/aks-secure-tls-bootstrap/client/internal/telemetry"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var bootstrapConfig = new(bootstrap.Config)

var (
	configFile string
	logFile    string
	verbose    bool
)

func init() {
	flag.StringVar(&configFile, "config-file", "", "path to the configuration file, settings in this file will take priority over command line arguments")
	flag.StringVar(&logFile, "log-file", "", "path to a file where logs will be written, will be created if it does not already exist")
	flag.BoolVar(&verbose, "verbose", false, "enable verbose log output")

	flag.StringVar(&bootstrapConfig.CloudProviderConfigPath, "cloud-provider-config", "", "path to the cloud provider config file")
	flag.StringVar(&bootstrapConfig.APIServerFQDN, "apiserver-fqdn", "", "FQDN of the apiserver")
	flag.StringVar(&bootstrapConfig.CustomClientID, "custom-client-id", "", "client ID of the user-assigned managed identity to use when requesting a token from IMDS - if not specified the kubelet identity will be used")
	flag.StringVar(&bootstrapConfig.AADResource, "aad-resource", "", "resource (audience) used to request JWT tokens from AAD for authentication")
	flag.StringVar(&bootstrapConfig.NextProto, "next-proto", "", "ALPN next proto value")
	flag.StringVar(&bootstrapConfig.KubeconfigPath, "kubeconfig", "", "path to the kubeconfig - if this file does not exist, the generated kubeconfig will be placed there")
	flag.StringVar(&bootstrapConfig.ClusterCAFilePath, "cluster-ca-file", "", "path to the cluster CA file")
	flag.StringVar(&bootstrapConfig.CredFilePath, "cred-file", "", "path to the file which will contain the PEM-encoded client certificate/key pair, referenced by the generated kubeconfig")
	flag.BoolVar(&bootstrapConfig.InsecureSkipTLSVerify, "insecure-skip-tls-verify", false, "skip TLS verification when connecting to the control plane")
	flag.BoolVar(&bootstrapConfig.EnsureAuthorizedClient, "ensure-authorized", false, "ensure the specified kubeconfig contains an authorized clientset before bootstrapping")
	flag.DurationVar(&bootstrapConfig.Deadline, "deadline", 3*time.Minute, "deadline within which bootstrapping must succeed")

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
	// defer calls are not executed on os.Exit
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM, syscall.SIGABRT, syscall.SIGKILL)
	exitCode := run(ctx)
	cancel()
	os.Exit(exitCode)
}

func run(ctx context.Context) int {
	logger, finalErr := configureLogging(logFile, verbose)
	if finalErr != nil {
		fmt.Printf("unable to construct zap logger: %s\n", finalErr)
		return 1
	}
	defer flush(logger)

	bootstrapClient, finalErr := bootstrap.NewClient(logger)
	if finalErr != nil {
		fmt.Printf("unable to construct bootstrap client: %s\n", finalErr)
		return 1
	}

	bootstrapStartTime := time.Now()
	bootstrapDeadline := bootstrapStartTime.Add(bootstrapConfig.Deadline)
	logger.Info("set bootstrap deadline", zap.Time("deadline", bootstrapDeadline))

	bootstrapCtx := telemetry.WithTracer(ctx, telemetry.NewTracer())
	bootstrapCtx, cancel := context.WithDeadline(bootstrapCtx, bootstrapDeadline)
	defer cancel()

	finalErr, errLog, traces := bootstrap.Bootstrap(bootstrapCtx, bootstrapClient, bootstrapConfig)
	bootstrapEndTime := time.Now()

	var exitCode int
	bootstrapResult := &bootstrap.Result{
		Status:              bootstrap.StatusSuccess,
		ElapsedMilliseconds: bootstrapEndTime.Sub(bootstrapStartTime).Milliseconds(),
		Errors:              errLog,
		Traces:              traces.GetLastNTraces(5), // only keep the last 5 traces to avoid truncating guest agent event data
		TraceSummary:        traces.GetTraceSummary(),
	}

	if finalErr != nil {
		bootstrapResult.Status = bootstrap.StatusFailure

		switch {
		case errors.Is(finalErr, context.Canceled):
			logger.Error("context was cancelled before bootstrapping could complete")
		case errors.Is(finalErr, context.DeadlineExceeded):
			logger.Error(
				"failed to successfully bootstrap before the specified deadline",
				zap.Error(errors.Unwrap(finalErr)),
				zap.Time("deadline", bootstrapDeadline),
				zap.Duration("deadlineDuration", bootstrapConfig.Deadline),
			)
		default:
			logger.Error("failed to bootstrap", zap.Error(errors.Unwrap(finalErr)))
		}

		bootstrapResult.FinalError = errors.Unwrap(finalErr).Error()
		exitCode = 1
	}

	bootstrapEvent := &bootstrap.Event{
		Start: bootstrapStartTime,
		End:   bootstrapEndTime,
	}
	eventFilePath, finalErr := bootstrapEvent.WriteWithResult(bootstrapResult)
	if finalErr != nil {
		logger.Error("unable to write bootstrap guest agent event to disk", zap.Error(finalErr))
	}
	if eventFilePath == "" {
		logger.Warn("guest agent event path does not exist, not guest agent event telemetry will be written", zap.String("eventMessage", bootstrapEvent.Message))
	} else {
		logger.Info("bootstrapping guest agent event telemetry written to disk", zap.String("path", eventFilePath))
	}

	return exitCode
}

func configureLogging(logFile string, verbose bool) (*zap.Logger, error) {
	encoderConfig := zap.NewProductionEncoderConfig()
	encoderConfig.TimeKey = "timestamp"
	encoderConfig.EncodeTime = zapcore.RFC3339NanoTimeEncoder

	level := zap.InfoLevel
	if verbose {
		level = zap.DebugLevel
	}

	cores := []zapcore.Core{
		zapcore.NewCore(
			zapcore.NewConsoleEncoder(encoderConfig),
			zapcore.AddSync(os.Stdout),
			level,
		),
	}

	if logFile != "" {
		if err := os.MkdirAll(filepath.Dir(logFile), 0755); err != nil {
			return nil, fmt.Errorf("failed to create log directory: %w", err)
		}
		logFileHandle, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return nil, fmt.Errorf("failed to open log file: %w", err)
		}
		cores = append(cores, zapcore.NewCore(
			zapcore.NewJSONEncoder(encoderConfig),
			zapcore.AddSync(logFileHandle),
			level,
		))
	}

	return zap.New(zapcore.NewTee(cores...)), nil
}

func flush(logger *zap.Logger) {
	// per guidance from: https://github.com/uber-go/zap/issues/328
	_ = logger.Sync()
}
