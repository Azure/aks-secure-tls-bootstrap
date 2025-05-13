package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/avast/retry-go/v4"
	"go.uber.org/zap"
	"k8s.io/client-go/tools/clientcmd"
)

// PerformBootstrapping performs the secure TLS bootstrapping process with
// the provided client, wrapped in a retry loop. The retry loop will continue
// indefinitely until the specified context is done, whether that be through a timeout or cancellation.
func PerformBootstrapping(ctx context.Context, logger *zap.Logger, client *Client, config *Config) (err error, bootstrapErrors map[ErrorType]int) {
	bootstrapErrors = map[ErrorType]int{}
	err = retry.Do(
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
			var bootstrapErr *BootstrapError
			if errors.As(err, &bootstrapErr) {
				bootstrapErrors[bootstrapErr.Type()]++
			}
			return true
		}),
		retry.Context(ctx),
		retry.WrapContextErrorWithLastError(true),
		retry.LastErrorOnly(true),
		retry.DelayType(retry.CombineDelay(retry.BackOffDelay, retry.RandomDelay)),
		retry.Delay(500*time.Millisecond),
		retry.MaxDelay(2*time.Second+500*time.Millisecond),
		retry.Attempts(0), // retry indefinitely according to the context deadline
	)
	return err, bootstrapErrors
}
