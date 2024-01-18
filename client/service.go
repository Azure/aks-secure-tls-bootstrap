package client

import (
	"context"
	"encoding/base64"
	"fmt"

	"github.com/Azure/aks-tls-bootstrap-client/client/pkg/datamodel"
	secureTLSBootstrapService "github.com/Azure/aks-tls-bootstrap-client/service/protos"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/oauth"
)

// used to wrap *grpc.ClientConn for unit testing
type grpcClientConn interface {
	Close() error
}

// serviceClientFactory is a func which can produce and return a new SecureTLSBootstrapServiceClient over a GRPC connection
type serviceClientFactory func(ctx context.Context, logger *zap.Logger, opts serviceClientFactoryOpts) (secureTLSBootstrapService.SecureTLSBootstrapServiceClient, grpcClientConn, error)

type serviceClientFactoryOpts struct {
	execCredential *datamodel.ExecCredential
	nextProto      string
	authToken      string
}

func secureTLSBootstrapServiceClientFactory(
	ctx context.Context,
	logger *zap.Logger,
	opts serviceClientFactoryOpts) (secureTLSBootstrapService.SecureTLSBootstrapServiceClient, grpcClientConn, error) {
	logger.Debug("decoding cluster CA data...")
	pemCAs, err := base64.StdEncoding.DecodeString(opts.execCredential.Spec.Cluster.CertificateAuthorityData)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode base64 cluster certificates: %w", err)
	}
	logger.Info("decoded cluster CA data")

	logger.Debug("generating TLS config for GRPC client connection...")
	tlsConfig, err := getTLSConfig(pemCAs, opts.nextProto, opts.execCredential.Spec.Cluster.InsecureSkipTLSVerify)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get TLS config: %w", err)
	}
	logger.Info("generated TLS config for GRPC client connection")

	logger.Debug("extracting server URL from exec credential...")
	serverURL, err := getServerURL(opts.execCredential)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get server URL from exec credential: %w", err)
	}
	logger.Info("extracted server URL from exec credential")

	logger.Debug("dialing TLS bootstrap server and creating GRPC connection...",
		zap.String("serverURL", serverURL),
		zap.Strings("tlsConfig.NextProtos", tlsConfig.NextProtos),
		zap.Bool("tlsConfig.InsecureSkipVerify", tlsConfig.InsecureSkipVerify))
	conn, err := grpc.DialContext(
		ctx, serverURL,
		grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)),
		grpc.WithPerRPCCredentials(oauth.TokenSource{
			TokenSource: oauth2.StaticTokenSource(&oauth2.Token{
				AccessToken: opts.authToken,
			}),
		}),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to dial client connection with context: %w", err)
	}
	logger.Info("dialed TLS bootstrap server and created GRPC connection")

	return secureTLSBootstrapService.NewSecureTLSBootstrapServiceClient(conn), conn, nil
}
