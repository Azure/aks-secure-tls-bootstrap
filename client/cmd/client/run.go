package main

import (
	"context"
	"fmt"

	"github.com/Azure/aks-secure-tls-bootstrap/client/internal/bootstrap"
	"go.uber.org/zap"
	"k8s.io/client-go/tools/clientcmd"
)

func run(ctx context.Context, logger *zap.Logger) int {
	if err := generateCredential(ctx, logger); err != nil {
		logger.Error("failed to generate a credential", zap.Error(err))
		return 1
	}
	return 0
}

func generateCredential(ctx context.Context, logger *zap.Logger) error {
	client, err := bootstrap.NewClient(logger)
	if err != nil {
		return fmt.Errorf("constructing bootstrap client: %w", err)
	}
	kubeconfigData, err := client.GetKubeletClientCredential(ctx, &bootstrapConfig)
	if err != nil {
		return fmt.Errorf("generating kubelet client credential: %w", err)
	}
	if err := clientcmd.WriteToFile(*kubeconfigData, bootstrapConfig.KubeconfigPath); err != nil {
		return fmt.Errorf("writing generated kubeconfig to disk: %w", err)
	}
	return nil
}
