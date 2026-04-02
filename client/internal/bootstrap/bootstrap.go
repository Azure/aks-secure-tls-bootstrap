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

// operationBudgets holds per-operation total-time budgets that span all retry attempts.
// Each context is derived from the overall deadline context before the retry loop starts,
// so its deadline (if set) limits the combined time all retries of that operation may use.
type operationBudgets struct {
	accessToken context.Context
	nonce       context.Context
	credential  context.Context
}

// ctxWithOptionalTimeout returns a child context with a deadline of timeout from now.
// If timeout is zero or negative, the parent context is returned unchanged with a no-op cancel.
func ctxWithOptionalTimeout(parent context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	if timeout <= 0 {
		return parent, func() {}
	}
	return context.WithTimeout(parent, timeout)
}

// Bootstrap performs the secure TLS bootstrapping wrapped in a retry loop.
// The retry loop will continue indefinitely until the specified context is done, whether that be through a timeout or cancellation.
// If all retries fail, the last error encountered will be returned in finalErr.
// In any case, a record of all errors encountered during the bootstrap process will be returned in errs, where error type is mapped to the corresponding occurrence count.
// Additionally, a map of traces is returned in traces, which records how long each bootstrapping step took, mapping task name to a corresponding time.Duration.
// Trace data is separately recorded for each retry attempt.
func Bootstrap(ctx context.Context, config *Config) (errLog ErrorLog, traces *telemetry.TraceStore, err error) {
	client := newClient(ctx)

	accessTokenBudgetCtx, accessTokenBudgetCancel := ctxWithOptionalTimeout(ctx, config.GetAccessTokenTotalTimeout)
	defer accessTokenBudgetCancel()
	nonceBudgetCtx, nonceBudgetCancel := ctxWithOptionalTimeout(ctx, config.GetNonceTotalTimeout)
	defer nonceBudgetCancel()
	credentialBudgetCtx, credentialBudgetCancel := ctxWithOptionalTimeout(ctx, config.GetCredentialTotalTimeout)
	defer credentialBudgetCancel()

	budgets := &operationBudgets{
		accessToken: accessTokenBudgetCtx,
		nonce:       nonceBudgetCtx,
		credential:  credentialBudgetCtx,
	}

	errLog = make(ErrorLog)
	traces = telemetry.NewTraceStore()
	err = retry.Do(
		func() error {
			defer func() {
				traces.Add(telemetry.GetTrace(ctx))
			}()
			kubeconfigData, err := client.bootstrap(ctx, config, budgets)
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
		retry.DelayType(retry.CombineDelay(retry.BackOffDelay, retry.RandomDelay)),
		retry.Delay(500*time.Millisecond),
		retry.MaxDelay(2*time.Second+500*time.Millisecond),
		retry.Attempts(0), // retry indefinitely according to the context deadline
	)

	return errLog, traces, err
}
