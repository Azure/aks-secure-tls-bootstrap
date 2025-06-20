package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/Azure/aks-secure-tls-bootstrap/client/internal/telemetry"
	"github.com/avast/retry-go/v4"
	"go.uber.org/zap"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

// PerformBootstrapping performs the secure TLS bootstrapping process with
// the provided client, wrapped in a retry loop. The retry loop will continue
// indefinitely until the specified context is done, whether that be through a timeout or cancellation.
func PerformBootstrapping(ctx context.Context, logger *zap.Logger, client *Client, config *Config) (err error, bootstrapErrors map[ErrorType]int, bootstrapRecording map[int]telemetry.Recording) {
	bootstrapErrors = map[ErrorType]int{}
	bootstrapRecording = map[int]telemetry.Recording{}

	var retryCount int
	err = retry.Do(
		func() error {
			defer func() {
				bootstrapRecording[retryCount] = telemetry.MustGetTaskRecorder(ctx).GetRecording()
				retryCount++
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

	return err, bootstrapErrors, bootstrapRecording
}

func writeKubeconfig(ctx context.Context, config *clientcmdapi.Config, path string) error {
	recorder := telemetry.MustGetTaskRecorder(ctx)
	recorder.Start("WriteKubeconfig")
	defer recorder.Stop("WriteKubeconfig")

	if err := clientcmd.WriteToFile(*config, path); err != nil {
		return &BootstrapError{
			errorType: ErrorTypeWriteKubeconfigFailure,
			inner:     fmt.Errorf("writing generated kubeconfig to disk: %w", err),
		}
	}
	return nil
}
