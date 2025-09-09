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
	"time"

	"github.com/Azure/aks-secure-tls-bootstrap/client/internal/bootstrap"
	"github.com/Azure/aks-secure-tls-bootstrap/client/internal/log"
	"github.com/Azure/aks-secure-tls-bootstrap/client/internal/telemetry"
	"go.uber.org/zap"
	"k8s.io/client-go/tools/clientcmd"
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
	flag.StringVar(&bootstrapConfig.CertDir, "cert-dir", "", "the directory where kubelet's new client certificate/key pair will be stored")
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
	logger, flush, err := log.NewProductionLogger(logFile, verbose)
	if err != nil {
		fmt.Printf("unable to construct zap logger: %s\n", err)
		return 1
	}
	defer flush()

	ctx = log.WithLogger(telemetry.WithTracing(ctx), logger)

	bootstrapClient, err := bootstrap.NewClient(ctx)
	if err != nil {
		fmt.Printf("unable to construct bootstrap client: %s\n", err)
		return 1
	}

	// setup the deadline
	bootstrapStartTime := time.Now()
	bootstrapDeadline := bootstrapStartTime.Add(bootstrapConfig.Deadline)
	logger.Info("set bootstrap deadline", zap.Time("deadline", bootstrapDeadline))
	bootstrapCtx, cancel := context.WithDeadline(ctx, bootstrapDeadline)
	defer cancel()

	// attempt bootstrapping
	kubeconfigData, err := bootstrapClient.Bootstrap(bootstrapCtx, bootstrapConfig)

	// process the result
	bootstrapEndTime := time.Now()
	bootstrapResult := &bootstrap.Result{
		Status:              bootstrap.StatusSuccess,
		ElapsedMilliseconds: bootstrapEndTime.Sub(bootstrapStartTime).Milliseconds(),
		Trace:               telemetry.GetTrace(bootstrapCtx),
	}
	defer emitGuestAgentEvent(logger, bootstrapStartTime, bootstrapEndTime, bootstrapResult)

	if err != nil {
		logger.Error("failed to bootstrap", zap.Error(err))
		bootstrapResult.Status = bootstrap.StatusFailure
		bootstrapResult.ErrorType = bootstrap.GetErrorType(err)
		bootstrapResult.Error = err.Error()
		return 1
	}

	if kubeconfigData != nil {
		if err := clientcmd.WriteToFile(*kubeconfigData, bootstrapConfig.KubeconfigPath); err != nil {
			logger.Error("unable to write kubeconfig file", zap.String("path", bootstrapConfig.KubeconfigPath), zap.Error(err))
			return 1
		}
		logger.Info("kubeconfig written to disk", zap.String("path", bootstrapConfig.KubeconfigPath))
	}

	return 0
}

func emitGuestAgentEvent(logger *zap.Logger, startTime, endTime time.Time, result *bootstrap.Result) {
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
