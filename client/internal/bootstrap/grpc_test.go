// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package bootstrap

import (
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/grpc/test/bufconn"

	"github.com/Azure/aks-secure-tls-bootstrap/client/internal/testutil"
	"github.com/stretchr/testify/assert"
)

func TestGRPC(t *testing.T) {
	var (
		clusterCACertPEM []byte
	)
	var err error
	clusterCACertPEM, _, err = testutil.GenerateCertPEM(testutil.CertTemplate{
		CommonName:   "hcp",
		Organization: "aks",
		IsCA:         true,
		Expiration:   time.Now().Add(time.Hour),
	})
	assert.NoError(t, err)

	tests := []struct {
		name        string
		setupFunc   func(*testing.T) *Config
		expectError bool
		errorSubstr []string
	}{
		{
			name: "cluster ca data cannot be read",
			setupFunc: func(t *testing.T) *Config {
				return &Config{
					ClusterCAFilePath: "does/not/exist.crt",
					NextProto:         "nextProto",
					APIServerFQDN:     "fqdn",
				}
			},
			expectError: true,
			errorSubstr: []string{"reading cluster CA data from does/not/exist.crt"},
		},
		{
			name: "cluster ca data is invalid",
			setupFunc: func(t *testing.T) *Config {
				tempDir := t.TempDir()
				caFilePath := filepath.Join(tempDir, "ca.crt")
				err := os.WriteFile(caFilePath, []byte("SGVsbG8gV29ybGQh"), os.ModePerm)
				assert.NoError(t, err)

				return &Config{
					ClusterCAFilePath: caFilePath,
					NextProto:         "nextProto",
					APIServerFQDN:     "fqdn",
				}
			},
			expectError: true,
			errorSubstr: []string{
				"failed to get TLS config",
				"unable to construct new cert pool using cluster CA data",
			},
		},
		{
			name: "client connection can be created with provided auth token",
			setupFunc: func(t *testing.T) *Config {
				lis := bufconn.Listen(1024)
				defer lis.Close()
				tempDir := t.TempDir()
				caFilePath := filepath.Join(tempDir, "ca.crt")
				err := os.WriteFile(caFilePath, clusterCACertPEM, os.ModePerm)
				assert.NoError(t, err)

				return &Config{
					ClusterCAFilePath: caFilePath,
					NextProto:         "nextProto",
					APIServerFQDN:     lis.Addr().String(),
				}
			},
			expectError: false,
			errorSubstr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := tt.setupFunc(t)
			client, closeFn, err := getServiceClient("token", cfg)

			if tt.expectError {
				assert.Error(t, err)
				for _, substr := range tt.errorSubstr {
					assert.Contains(t, err.Error(), substr)
				}
				assert.Nil(t, client)
				assert.Nil(t, closeFn)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, client)
				assert.NotNil(t, closeFn)
				_ = closeFn()
			}
		})
	}
}
func TestGetTLSConfig(t *testing.T) {
	var (
		clusterCACertPEM []byte
	)
	var err error
	clusterCACertPEM, _, err = testutil.GenerateCertPEM(testutil.CertTemplate{
		CommonName:   "hcp",
		Organization: "aks",
		IsCA:         true,
		Expiration:   time.Now().Add(time.Hour),
	})
	assert.NoError(t, err)
	rootPool := x509.NewCertPool()
	ok := rootPool.AppendCertsFromPEM(clusterCACertPEM)
	assert.True(t, ok)

	tests := []struct {
		name               string
		nextProto          string
		insecureSkipVerify bool
		expectedNextProtos []string
	}{
		{
			name:               "without nextProto",
			nextProto:          "",
			insecureSkipVerify: false,
			expectedNextProtos: nil,
		},
		{
			name:               "with nextProto",
			nextProto:          "bootstrap",
			insecureSkipVerify: false,
			expectedNextProtos: []string{"bootstrap", "h2"},
		},
		{
			name:               "insecureSkipVerify false",
			nextProto:          "nextProto",
			insecureSkipVerify: false,
			expectedNextProtos: []string{"nextProto", "h2"},
		},
		{
			name:               "insecureSkipVerify true",
			nextProto:          "nextProto",
			insecureSkipVerify: true,
			expectedNextProtos: []string{"nextProto", "h2"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config, err := getTLSConfig(clusterCACertPEM, tt.nextProto, tt.insecureSkipVerify)
			assert.NoError(t, err)
			assert.NotNil(t, config)
			assert.Equal(t, tt.expectedNextProtos, config.NextProtos)
			assert.Equal(t, tt.insecureSkipVerify, config.InsecureSkipVerify)
			assert.True(t, config.RootCAs.Equal(rootPool))
		})
	}
}
