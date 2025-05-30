// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package bootstrap

import (
	"crypto/x509"
	"os"
	"path/filepath"
	"time"
	"testing"
	"strings"

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
	
	t.Run("cluster ca data cannot be read", func(t *testing.T) {
		serviceClient, close, err := getServiceClient("token", &Config{
			ClusterCAFilePath: "does/not/exist.crt",
			NextProto:         "nextProto",
			APIServerFQDN:     "fqdn",
		})

		assert.Nil(t, serviceClient)
		assert.Nil(t, close)
		assert.NotNil(t, err)
		assert.Equal(t, strings.Contains(err.Error(), "reading cluster CA data from does/not/exist.crt"), true)
	})

	t.Run("cluster ca data is invalid", func(t *testing.T) {
		tempDir := t.TempDir()
		caFilePath := filepath.Join(tempDir, "ca.crt")
		err := os.WriteFile(caFilePath, []byte("SGVsbG8gV29ybGQh"), os.ModePerm)
		assert.NoError(t, err)

		serviceClient, close, err := getServiceClient("token", &Config{
			ClusterCAFilePath: caFilePath,
			NextProto:         "nextProto",
			APIServerFQDN:     "fqdn",
		})

		assert.Nil(t, serviceClient)
		assert.Nil(t, close)
		assert.NotNil(t, err)
		assert.Equal(t, strings.Contains(err.Error(), "failed to get TLS config"), true)
		assert.Equal(t, strings.Contains(err.Error(), "unable to construct new cert pool using cluster CA data"), true)
	})

	t.Run("client connection can be created with provided auth token", func(t *testing.T) {
		tempDir := t.TempDir()
		caFilePath := filepath.Join(tempDir, "ca.crt")
		err := os.WriteFile(caFilePath, clusterCACertPEM, os.ModePerm)
		assert.NoError(t, err)

		lis := bufconn.Listen(1024)
		defer lis.Close()

		serviceClient, close, err := getServiceClient("token", &Config{
			ClusterCAFilePath: caFilePath,
			NextProto:         "nextProto",
			APIServerFQDN:     lis.Addr().String(),
		})

		assert.NoError(t, err)
		assert.NotNil(t, close)
		assert.NotNil(t, serviceClient)

		_ = close()
	})

	t.Run("getTLSConfig tests", func(t *testing.T) {
		rootPool := x509.NewCertPool()
		ok := rootPool.AppendCertsFromPEM(clusterCACertPEM)
		assert.True(t, ok)

		tests := []struct {
			name			  string
			nextProto         string
			insecureSkipVerify bool
			expectedNextProtos []string
		}{
			{
				name:              "without nextProto",
				nextProto:         "",
				insecureSkipVerify: false,
				expectedNextProtos: nil,
			},
			{
				name:              "with nextProto",
				nextProto:         "bootstrap",
				insecureSkipVerify: false,
				expectedNextProtos: []string{"bootstrap", "h2"},
			},
			{
				name:              "insecureSkipVerify false",
				nextProto:         "nextProto",
				insecureSkipVerify: false,
				expectedNextProtos: nil,
			},
			{
				name:              "insecureSkipVerify true",
				nextProto:         "nextProto",
				insecureSkipVerify: true,
				expectedNextProtos: nil,
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
	})
}