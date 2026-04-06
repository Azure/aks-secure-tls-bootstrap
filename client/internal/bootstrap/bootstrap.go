// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package bootstrap

import (
	"context"

	"k8s.io/client-go/tools/clientcmd"
)

// Bootstrap performs the secure TLS bootstrapping protocol using the specified config.
func Bootstrap(ctx context.Context, config *Config) error {
	kubeconfigData, err := newClient(ctx).bootstrap(ctx, config)
	if err != nil {
		return err
	}
	return clientcmd.WriteToFile(kubeconfigData, config.KubeconfigPath)
}
