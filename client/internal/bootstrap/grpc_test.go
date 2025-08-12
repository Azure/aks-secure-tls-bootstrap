// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package bootstrap

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/grpc/test/bufconn"

	"github.com/Azure/aks-secure-tls-bootstrap/client/internal/log"
	"github.com/Azure/aks-secure-tls-bootstrap/client/internal/testutil"
	"github.com/stretchr/testify/assert"
)

func TestGetServiceClient(t *testing.T) {
	clusterCACertPEM, _, err := testutil.GenerateCertPEM(testutil.CertTemplate{
		CommonName:   "hcp",
		Organization: "aks",
		IsCA:         true,
		Expiration:   time.Now().Add(time.Hour),
	})
	assert.NoError(t, err)

	tests := []struct {
		name        string
		setupFunc   func(*testing.T) *Config
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
			errorSubstr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := tt.setupFunc(t)
			client, closeFn, err := getServiceClient("token", cfg)

			if len(tt.errorSubstr) > 0 {
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
				closeFn := closeFn()
				assert.NoError(t, closeFn)
			}
		})
	}
}

func TestGetTLSConfig(t *testing.T) {
	clusterCACertPEM, _, err := testutil.GenerateCertPEM(testutil.CertTemplate{
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

func TestGetGRPCOnRetryCallbackFunc(t *testing.T) {
	t.Cleanup(func() {
		lastGRPCRetryError = nil
	})
	ctx := log.NewTestContext()
	errs := []error{errors.New("e0"), errors.New("e1"), errors.New("e2")}

	fn := getGRPCOnRetryCallbackFunc()
	for idx, err := range errs {
		fn(ctx, uint(idx+1), err)
	}
	assert.Equal(t, errs[len(errs)-1], lastGRPCRetryError)
}

func TestWithLastGRPCRetryErrorIfDeadlineExceeded(t *testing.T) {
	cases := []struct {
		name               string
		err                error
		lastGRPCRetryError error
		expectedErr        error
	}{
		{
			name:               "last GRPC retry error is nil",
			err:                errors.New("non-retryable error"),
			lastGRPCRetryError: nil,
			expectedErr:        errors.New("non-retryable error"),
		},
		{
			name:               "err is not a context.DeadlineExceeded",
			err:                errors.New("an error"),
			lastGRPCRetryError: errors.New("service unavailable"),
			expectedErr:        errors.New("an error"),
		},
		{
			name:               "err is a context.DeadlineExceeded and last GRPC retry error is non-nil",
			err:                context.DeadlineExceeded,
			lastGRPCRetryError: errors.New("service unavailable"),
			expectedErr:        fmt.Errorf("%w: last error: %s", context.DeadlineExceeded, errors.New("service unavailable")),
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Cleanup(func() {
				lastGRPCRetryError = nil
			})
			lastGRPCRetryError = c.lastGRPCRetryError

			assert.Equal(t, c.expectedErr, withLastGRPCRetryErrorIfDeadlineExceeded(c.err))
		})
	}
}
