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

func PerformBootstrapping(ctx context.Context, logger *zap.Logger, client *Client, config *Config) error {
	return retry.Do(
		func() error {
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
			return !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded)
		}),
		retry.DelayType(retry.DefaultDelayType), // backoff + random jitter
		retry.Delay(500*time.Millisecond),
		retry.MaxDelay(3*time.Second),
		retry.LastErrorOnly(true),
	)
}
