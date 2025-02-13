// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package bootstrap

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"

	"github.com/Azure/aks-secure-tls-bootstrap/client/internal/consts"
	akssecuretlsbootstrapv1 "github.com/Azure/aks-secure-tls-bootstrap/service/pkg/gen/akssecuretlsbootstrap/v1"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/oauth"
)

// serviceClientFactoryFunc provides an interface to produce and return a new SecureTLSBootstrapServiceClient over a GRPC connection.
// Fake implementations are provided within unit tests.
type serviceClientFactoryFunc func(logger *zap.Logger, token string, cfg *Config) (akssecuretlsbootstrapv1.SecureTLSBootstrapServiceClient, func() error, error)

func serviceClientFactory(logger *zap.Logger, token string, cfg *Config) (akssecuretlsbootstrapv1.SecureTLSBootstrapServiceClient, func() error, error) {
	clusterCAData, err := os.ReadFile(cfg.ClusterCAFilePath)
	if err != nil {
		return nil, nil, fmt.Errorf("reading cluster CA data from %s: %w", cfg.ClusterCAFilePath, err)
	}
	logger.Info("read cluster CA data", zap.String("path", cfg.ClusterCAFilePath))

	tlsConfig, err := getTLSConfig(clusterCAData, cfg.NextProto, cfg.InsecureSkipTLSVerify)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get TLS config: %w", err)
	}

	conn, err := grpc.NewClient(
		fmt.Sprintf("%s:443", cfg.APIServerFQDN),
		grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)),
		grpc.WithPerRPCCredentials(oauth.TokenSource{
			TokenSource: oauth2.StaticTokenSource(&oauth2.Token{
				AccessToken: token,
			}),
		}),
		grpc.WithUserAgent(consts.SecureTLSBootstrapClientUserAgentValue),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to dial client connection with context: %w", err)
	}
	logger.Info("dialed TLS bootstrap server and created GRPC connection")

	return akssecuretlsbootstrapv1.NewSecureTLSBootstrapServiceClient(conn), conn.Close, nil
}

func getTLSConfig(caPEM []byte, nextProto string, insecureSkipVerify bool) (*tls.Config, error) {
	roots := x509.NewCertPool()
	if ok := roots.AppendCertsFromPEM(caPEM); !ok {
		return nil, fmt.Errorf("unable to construct new cert pool using cluster CA data")
	}

	//nolint: gosec // let server dictate min TLS version
	tlsConfig := &tls.Config{
		RootCAs:            roots,
		InsecureSkipVerify: insecureSkipVerify,
	}
	if nextProto != "" {
		tlsConfig.NextProtos = []string{nextProto, "h2"}
	}

	return tlsConfig, nil
}
