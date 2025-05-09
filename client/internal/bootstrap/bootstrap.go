package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/avast/retry-go"
	"go.uber.org/zap"
	"k8s.io/client-go/tools/clientcmd"
)

func PerformBootstrapping(ctx context.Context, logger *zap.Logger, client *Client, config *Config) (multiErr error, bootstrapErrorFreqs map[ErrorType]int) {
	bootstrapErrorFreqs = map[ErrorType]int{}
	multiErr = retry.Do(
		func() error {
			if err := ctx.Err(); err != nil {
				return err // return the context error if the done channel is closed
			}
			kubeconfigData, err := client.BootstrapKubeletClientCredential(ctx, config)
			if err != nil {
				return err
			}
			if kubeconfigData == nil {
				return nil
			}
			if err := clientcmd.WriteToFile(*kubeconfigData, config.KubeconfigPath); err != nil {
				return &BootstrapError{
					errorType: ErrorTypeWriteKubeconfigFailure,
					inner:     fmt.Errorf("writing generated kubeconfig to disk: %w", err),
				}
			}
			return nil
		},
		retry.RetryIf(func(err error) bool {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return false
			}
			var bootstrapErr *BootstrapError
			if errors.As(err, &bootstrapErr) {
				bootstrapErrorFreqs[bootstrapErr.Type()]++
			}
			return true
		}),
		retry.Attempts(1000),                    // retry indefinitely according to the context deadline
		retry.DelayType(retry.DefaultDelayType), // backoff + random jitter
		retry.Delay(500*time.Millisecond),
		retry.MaxDelay(2*time.Second+500*time.Millisecond),
	)
	return multiErr, bootstrapErrorFreqs
}
