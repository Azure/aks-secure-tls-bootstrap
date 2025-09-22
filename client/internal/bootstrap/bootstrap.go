// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package bootstrap

import (
	"context"
	"errors"
	"time"

	"github.com/Azure/aks-secure-tls-bootstrap/client/internal/telemetry"
	"github.com/avast/retry-go/v4"
	"k8s.io/client-go/tools/clientcmd"
)

// Bootstrap performs the secure TLS bootstrapping wrapped in a retry loop.
// The retry loop will continue indefinitely until the specified context is done, whether that be through a timeout or cancellation.
// If all retries fail, the last error encountered will be returned in finalErr.
// In any case, a record of all errors encountered during the bootstrap process will be returned in errs, where error type is mapped to the corresponding occurrence count.
// Additionally, a map of traces is returned in traces, which records how long each bootstrapping step took, mapping task name to a corresponding time.Duration.
// Trace data is separately recorded for each retry attempt.
func Bootstrap(ctx context.Context, config *Config) (err error, errLog ErrorLog, traces *telemetry.TraceStore) {
	client := newClient(ctx)

	errLog = make(ErrorLog)
	traces = telemetry.NewTraceStore()
	err = retry.Do(
		func() error {
			defer func() {
				traces.Add(telemetry.GetTrace(ctx))
			}()
			kubeconfigData, err := client.bootstrap(ctx, config)
			if err != nil {
				return err
			}
			if err := clientcmd.WriteToFile(kubeconfigData, config.KubeconfigPath); err != nil {
				return err
			}
			return nil
		},
		retry.RetryIf(func(err error) bool {
			var bootstrapErr *bootstrapError
			if !errors.As(err, &bootstrapErr) {
				return false
			}
			errLog[bootstrapErr.errorType]++
			return bootstrapErr.retryable
		}),
		retry.Context(ctx),
		retry.WrapContextErrorWithLastError(true),
		retry.LastErrorOnly(true),
		retry.DelayType(retry.CombineDelay(retry.BackOffDelay, retry.RandomDelay)),
		retry.Delay(500*time.Millisecond),
		retry.MaxDelay(2*time.Second+500*time.Millisecond),
		retry.Attempts(0), // retry indefinitely according to the context deadline
	)

	return err, errLog, traces
}
