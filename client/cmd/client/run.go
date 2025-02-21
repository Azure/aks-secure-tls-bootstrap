package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/Azure/aks-secure-tls-bootstrap/client/internal/bootstrap"
	"github.com/Azure/aks-secure-tls-bootstrap/client/internal/event"
	"github.com/avast/retry-go"
	"go.uber.org/zap"
	"k8s.io/client-go/tools/clientcmd"
)

func run(ctx context.Context, logger *zap.Logger) int {
	var code int

	hostName, err := os.Hostname()
	if err != nil {
		logger.Error("unable to resolve hostname for bootstrap result", zap.Error(err))
	}
	result := &event.BootstrapResult{
		Hostname: hostName,
	}

	start := time.Now()
	dl := start.Add(bootstrapConfig.Deadline)
	logger.Info("set bootstrap deadline", zap.Time("deadline", dl))

	bootstrapEvent := &event.Event{
		Name:    "AKS.performSecureTLSBootstrapping",
		Message: "Succeeded",
		Start:   start,
	}
	defer func() {
		if err := bootstrapEvent.Write(); err != nil {
			logger.Error("unable to write guest agent event data to disk", zap.Error(err))
		}
	}()

	err = generateCredential(ctx, logger, dl)
	bootstrapEvent.End = time.Now()
	if err != nil {
		logger.Error("failed to bootstrap", zap.Error(err))
		logs, err := tailLogFile()
		if err != nil {
			logger.Error("failed to read log file", zap.Error(err))
		}
		result.Status = "Failed"
		result.Log = logs
		code = 1
	}

	rawResult, err := json.Marshal(result)
	if err != nil {
		logger.Error("failed to marshal bootstrap result", zap.Error(err))
	}
	bootstrapEvent.Message = string(rawResult)
	return code
}

func generateCredential(ctx context.Context, logger *zap.Logger, dl time.Time) error {
	client, err := bootstrap.NewClient(logger)
	if err != nil {
		return fmt.Errorf("constructing bootstrap client: %w", err)
	}
	retryIf := func(err error) bool {
		return !errors.Is(err, context.Canceled) && !time.Now().After(dl)
	}
	generate := func() error {
		kubeconfigData, err := client.GetKubeletClientCredential(ctx, &bootstrapConfig)
		if err != nil {
			return fmt.Errorf("generating kubelet client credential: %w", err)
		}
		if kubeconfigData != nil {
			if err := clientcmd.WriteToFile(*kubeconfigData, bootstrapConfig.KubeconfigPath); err != nil {
				return fmt.Errorf("writing generated kubeconfig to disk: %w", err)
			}
		}
		return nil
	}
	return retry.Do(
		generate,
		retry.RetryIf(retryIf),
		retry.DelayType(retry.FixedDelay),
		retry.Delay(2*time.Second),
		retry.LastErrorOnly(true),
	)
}

func tailLogFile() (string, error) {
	logData, err := os.ReadFile(logFile)
	if err != nil {
		return "", err
	}
	logString := string(logData)
	lines := strings.Split(logString, "\n")
	return strings.Join(lines[len(lines)-20:], "\n"), nil
}
