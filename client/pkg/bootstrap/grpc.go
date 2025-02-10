// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package bootstrap

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"

	"github.com/Azure/aks-secure-tls-bootstrap/client/pkg/consts"
	secureTLSBootstrapService "github.com/Azure/aks-secure-tls-bootstrap/service/protos"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/oauth"
)

// serviceClientFactory provides an interface to produce and return a new SecureTLSBootstrapServiceClient over a GRPC connection
type serviceClientFactoryFunc func(ctx context.Context, logger *zap.Logger, cfg *serviceClientFactoryConfig) (secureTLSBootstrapService.SecureTLSBootstrapServiceClient, *grpc.ClientConn, error)

type serviceClientFactoryConfig struct {
	clusterCAFilePath     string
	insecureSkipTLSVerify bool
	fqdn                  string
	nextProto             string
	authToken             string
}

func secureTLSBootstrapServiceClientFactory(
	ctx context.Context,
	logger *zap.Logger,
	cfg *serviceClientFactoryConfig) (secureTLSBootstrapService.SecureTLSBootstrapServiceClient, *grpc.ClientConn, error) {
	clusterCAData, err := os.ReadFile(cfg.clusterCAFilePath)
	if err != nil {
		return nil, nil, fmt.Errorf("reading cluster CA data from %s: %w", cfg.clusterCAFilePath, err)
	}
	logger.Info("read cluster CA data", zap.String("path", cfg.clusterCAFilePath))

	tlsConfig, err := getTLSConfig(clusterCAData, cfg.nextProto, cfg.insecureSkipTLSVerify)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get TLS config: %w", err)
	}
	conn, err := grpc.DialContext(
		ctx,
		fmt.Sprintf("%s:443", cfg.fqdn),
		grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)),
		grpc.WithPerRPCCredentials(oauth.TokenSource{
			TokenSource: oauth2.StaticTokenSource(&oauth2.Token{
				AccessToken: cfg.authToken,
			}),
		}),
		grpc.WithUserAgent(consts.SecureTLSBootstrapClientUserAgentValue),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to dial client connection with context: %w", err)
	}
	logger.Info("dialed TLS bootstrap server and created GRPC connection")

	return secureTLSBootstrapService.NewSecureTLSBootstrapServiceClient(conn), conn, nil
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
