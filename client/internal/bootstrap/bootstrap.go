package bootstrap

import (
	"context"
	"fmt"

	"github.com/Azure/aks-secure-tls-bootstrap/client/internal/errors"
	"k8s.io/client-go/tools/clientcmd"
)

// Bootstrap performs the secure TLS bootstrapping process using the provided bootstrap client and configuration.
func Bootstrap(ctx context.Context, client *Client, config *Config) error {
	kubeconfigData, err := client.BootstrapKubeletClientCredential(ctx, config)
	if err != nil {
		return err
	}
	if kubeconfigData == nil {
		return nil
	}
	if err := clientcmd.WriteToFile(*kubeconfigData, config.KubeconfigPath); err != nil {
		return &errors.BootstrapError{
			Type:  errors.BootstrapErrorTypeWriteKubeconfigFailure,
			Inner: fmt.Errorf("writing generated kubeconfig to disk: %w", err),
		}
	}
	return nil
}
