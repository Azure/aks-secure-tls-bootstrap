// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/Azure/aks-secure-tls-bootstrap/client/internal/telemetry"
	"github.com/avast/retry-go/v4"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

// Bootstrap performs the secure TLS bootstrapping process with the provided client, wrapped in a retry loop.
// The retry loop will continue indefinitely until the specified context is done, whether that be through a timeout or cancellation.
// If all retries fail, the last error encountered will be returned in finalErr.
// In any case, a record of all errors encountered during the bootstrap process will be returned in errs, where error type is mapped to the corresponding occurrence count.
// Additionally, a map of traces is returned in traces, which records how long each bootstrapping step took, mapping task name to a corresponding time.Duration.
// Trace data is separately recorded for each retry attempt.
func Bootstrap(ctx context.Context, client *Client, config *Config) (finalErr error, errLog map[ErrorType]int, traces *telemetry.TraceStore) {
	errLog = make(map[ErrorType]int)
	traces = telemetry.NewTraceStore()

	finalErr = retry.Do(
		func() error {
			defer func() {
				traces.Add(telemetry.MustGetTracer(ctx).GetTrace())
			}()

			kubeconfigData, err := client.BootstrapKubeletClientCredential(ctx, config)
			if err != nil {
				return err
			}
			if kubeconfigData == nil {
				return nil
			}
			if err := writeKubeconfig(ctx, kubeconfigData, config.KubeconfigPath); err != nil {
				return err
			}
			return nil
		},
		retry.RetryIf(func(err error) bool {
			var bootstrapErr *BootstrapError
			if !errors.As(err, &bootstrapErr) {
				return false
			}
			errLog[bootstrapErr.Type()]++
			return bootstrapErr.Retryable()
		}),
		retry.Context(ctx),
		retry.WrapContextErrorWithLastError(true),
		retry.LastErrorOnly(true),
		retry.DelayType(retry.CombineDelay(retry.BackOffDelay, retry.RandomDelay)),
		retry.Delay(500*time.Millisecond),
		retry.MaxDelay(2*time.Second+500*time.Millisecond),
		retry.Attempts(0), // retry indefinitely according to the context deadline
	)

	return finalErr, errLog, traces
}

func writeKubeconfig(ctx context.Context, config *clientcmdapi.Config, path string) error {
	traceName := "WriteKubeconfig"
	tracer := telemetry.MustGetTracer(ctx)
	tracer.StartSpan(traceName)
	defer tracer.EndSpan(traceName)

	if err := os.MkdirAll(filepath.Dir(path), 0600); err != nil {
		return &BootstrapError{
			errorType: ErrorTypeWriteKubeconfigFailure,
			inner:     fmt.Errorf("creating parent directories for kubeconfig path: %w", err),
		}
	}

	if err := clientcmd.WriteToFile(*config, path); err != nil {
		return &BootstrapError{
			errorType: ErrorTypeWriteKubeconfigFailure,
			inner:     fmt.Errorf("writing generated kubeconfig to disk: %w", err),
		}
	}
	return nil
}
