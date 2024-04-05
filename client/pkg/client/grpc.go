// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"

	secureTLSBootstrapService "github.com/Azure/aks-secure-tls-bootstrap/service/protos"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/oauth"
)

// serviceDialerFunc provides an interface to produce and return a new SecureTLSBootstrapServiceClient over a GRPC connection
type serviceDialerFunc func(ctx context.Context, logger *zap.Logger, cfg *dialerConfig) (*dialResult, error)

type dialResult struct {
	serviceClient secureTLSBootstrapService.SecureTLSBootstrapServiceClient
	grpcConn      *grpc.ClientConn
}

type dialerConfig struct {
	clusterCAData         []byte
	insecureSkipTLSVerify bool
	fqdn                  string
	nextProto             string
	authToken             string
}

func secureTLSBootstrapServiceDialer(ctx context.Context, logger *zap.Logger, cfg *dialerConfig) (*dialResult, error) {
	logger.Debug("generating TLS config for GRPC client connection...")
	tlsConfig, err := getTLSConfig(cfg.clusterCAData, cfg.nextProto, cfg.insecureSkipTLSVerify)
	if err != nil {
		return nil, fmt.Errorf("failed to get TLS config: %w", err)
	}
	logger.Info("generated TLS config for GRPC client connection")

	logger.Debug("dialing TLS bootstrap server and creating GRPC connection...",
		zap.String("fqdn", cfg.fqdn),
		zap.Strings("tlsConfig.NextProtos", tlsConfig.NextProtos),
		zap.Bool("tlsConfig.InsecureSkipVerify", tlsConfig.InsecureSkipVerify))
	conn, err := grpc.DialContext(
		ctx,
		cfg.fqdn,
		grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)),
		grpc.WithPerRPCCredentials(oauth.TokenSource{
			TokenSource: oauth2.StaticTokenSource(&oauth2.Token{
				AccessToken: cfg.authToken,
			}),
		}),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to dial client connection with context: %w", err)
	}
	logger.Info("dialed TLS bootstrap server and created GRPC connection")

	return &dialResult{
		serviceClient: secureTLSBootstrapService.NewSecureTLSBootstrapServiceClient(conn),
		grpcConn:      conn,
	}, nil
}

func getTLSConfig(caPEM []byte, nextProto string, insecureSkipVerify bool) (*tls.Config, error) {
	roots := x509.NewCertPool()
	if ok := roots.AppendCertsFromPEM(caPEM); !ok {
		return nil, fmt.Errorf("unable to construct new cert pool using provided cluster CA data")
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
