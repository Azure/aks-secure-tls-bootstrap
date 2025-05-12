// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package bootstrap

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"time"

	internalhttp "github.com/Azure/aks-secure-tls-bootstrap/client/internal/http"
	akssecuretlsbootstrapv1 "github.com/Azure/aks-secure-tls-bootstrap/service/pkg/gen/akssecuretlsbootstrap/v1"
	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/retry"
	"golang.org/x/oauth2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/oauth"
)

// getServiceClientFunc returns a new SecureTLSBootstrapServiceClient over a gRPC connection, fake implementations given in unit tests.
type getServiceClientFunc func(token string, cfg *Config) (akssecuretlsbootstrapv1.SecureTLSBootstrapServiceClient, func() error, error)

func getServiceClient(token string, cfg *Config) (akssecuretlsbootstrapv1.SecureTLSBootstrapServiceClient, func() error, error) {
	clusterCAData, err := os.ReadFile(cfg.ClusterCAFilePath)
	if err != nil {
		return nil, nil, fmt.Errorf("reading cluster CA data from %s: %w", cfg.ClusterCAFilePath, err)
	}

	tlsConfig, err := getTLSConfig(clusterCAData, cfg.NextProto, cfg.InsecureSkipTLSVerify)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get TLS config: %w", err)
	}

	conn, err := grpc.NewClient(
		fmt.Sprintf("%s:443", cfg.APIServerFQDN),
		grpc.WithUserAgent(internalhttp.GetUserAgentValue()),
		grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)),
		grpc.WithPerRPCCredentials(oauth.TokenSource{
			TokenSource: oauth2.StaticTokenSource(&oauth2.Token{
				AccessToken: token,
			}),
		}),
		grpc.WithUnaryInterceptor(retry.UnaryClientInterceptor(
			retry.WithBackoff(retry.BackoffExponentialWithJitterBounded(100*time.Millisecond, 0.75, 2*time.Second)),
			retry.WithCodes(codes.Aborted, codes.Unavailable),
			retry.WithMax(30),
		)),
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
