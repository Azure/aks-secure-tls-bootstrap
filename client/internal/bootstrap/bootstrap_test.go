// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package bootstrap

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"k8s.io/client-go/tools/clientcmd/api"
)

func TestBootstrap(t *testing.T) {
	cases := []struct {
		name             string
		bootstrapFunc    func(ctx context.Context, config *Config) (*api.Config, error)
		expectKubeconfig func(t *testing.T, path string)
		expectedError    error
	}{
		{
			name: "bootstrapping returns an error",
			bootstrapFunc: func(ctx context.Context, config *Config) (*api.Config, error) {
				return nil, errors.New("failed to bootstrap")
			},
			expectedError: errors.New("failed to bootstrap"),
		},
		{
			name: "bootstrapping returns no error and no kubeconfig data",
			bootstrapFunc: func(ctx context.Context, config *Config) (*api.Config, error) {
				return nil, nil
			},
			expectKubeconfig: func(t *testing.T, path string) {
				_, err := os.Stat(path)
				assert.True(t, os.IsNotExist(err))
			},
			expectedError: nil,
		},
		{
			name: "bootstrapping returns kubeconfig data without error",
			bootstrapFunc: func(ctx context.Context, config *Config) (*api.Config, error) {
				return &api.Config{
					Clusters: map[string]*api.Cluster{
						"default-cluster": {
							Server: "server",
						},
					},
					AuthInfos: map[string]*api.AuthInfo{
						"default-auth": {
							ClientCertificate: "cert",
							ClientKey:         "key",
						},
					},
					Contexts: map[string]*api.Context{
						"default-context": {
							Cluster:  "default-cluster",
							AuthInfo: "default-auth",
						},
					},
					CurrentContext: "default-context",
				}, nil
			},
			expectKubeconfig: func(t *testing.T, path string) {
				info, err := os.Stat(path)
				assert.NoError(t, err)
				assert.NotZero(t, info.Size())
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ctx := context.Background()
			kubeconfigPath := filepath.Join(t.TempDir(), "kubeconfig")
			bootstrapFunc = c.bootstrapFunc

			err := Bootstrap(ctx, &Config{KubeconfigPath: kubeconfigPath})
			if c.expectedError != nil {
				assert.EqualError(t, err, c.expectedError.Error())
			} else {
				assert.NoError(t, err)
			}
			if c.expectKubeconfig != nil {
				c.expectKubeconfig(t, kubeconfigPath)
			}
		})
	}
}
