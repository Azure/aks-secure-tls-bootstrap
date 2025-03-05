// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package bootstrap

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"

	internalhttp "github.com/Azure/aks-secure-tls-bootstrap/client/internal/http"
	akssecuretlsbootstrapv1 "github.com/Azure/aks-secure-tls-bootstrap/service/pkg/gen/akssecuretlsbootstrap/v1"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/oauth"
)

// closerFunc closes a gRPC connection.
type closerFunc func() error

func (c closerFunc) close(logger *zap.Logger) {
	if err := c(); err != nil {
		logger.Error("closing gRPC client connection: %s", zap.Error(err))
	}
}

// getServiceClientFunc returns a new SecureTLSBootstrapServiceClient over a gRPC connection, fake implementations given in unit tests.
type getServiceClientFunc func(token string, config *Config) (akssecuretlsbootstrapv1.SecureTLSBootstrapServiceClient, closerFunc, error)

func getServiceClient(token string, config *Config) (akssecuretlsbootstrapv1.SecureTLSBootstrapServiceClient, closerFunc, error) {
	clusterCAData, err := os.ReadFile(config.ClusterCAFilePath)
	if err != nil {
		return nil, nil, fmt.Errorf("reading cluster CA data from %s: %w", config.ClusterCAFilePath, err)
	}

	tlsConfig, err := getTLSConfig(clusterCAData, config.NextProto, config.InsecureSkipTLSVerify)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get TLS config: %w", err)
	}

	conn, err := grpc.NewClient(
		fmt.Sprintf("%s:443", config.APIServerFQDN),
		grpc.WithDefaultCallOptions(grpc.WaitForReady(true)),
		grpc.WithUserAgent(internalhttp.GetUserAgentValue()),
		grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)),
		grpc.WithPerRPCCredentials(oauth.TokenSource{
			TokenSource: oauth2.StaticTokenSource(&oauth2.Token{
				AccessToken: token,
			}),
		}),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to dial client connection with context: %w", err)
	}

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
