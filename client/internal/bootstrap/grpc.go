// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package bootstrap

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"time"

	internalhttp "github.com/Azure/aks-secure-tls-bootstrap/client/internal/http"
	"github.com/Azure/aks-secure-tls-bootstrap/client/internal/log"
	akssecuretlsbootstrapv1 "github.com/Azure/aks-secure-tls-bootstrap/service/pkg/gen/akssecuretlsbootstrap/v1"
	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/retry"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/oauth"
	"google.golang.org/grpc/status"
)

// used to store any errors encountered by the gRPC client when making RPCs to the remote
// within the retry loop configured by retry.UnaryClientInterceptor
var lastGRPCRetryError error

// closeFunc closes a gRPC client connection, fake implementations given in unit tests.
type closeFunc func() error

// getServiceClientFunc returns a new SecureTLSBootstrapServiceClient over a gRPC connection, fake implementations given in unit tests.
type getServiceClientFunc func(token string, cfg *Config) (akssecuretlsbootstrapv1.SecureTLSBootstrapServiceClient, closeFunc, error)

func getServiceClient(token string, cfg *Config) (akssecuretlsbootstrapv1.SecureTLSBootstrapServiceClient, closeFunc, error) {
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
		grpc.WithUserAgent(internalhttp.UserAgent()),
		grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)),
		grpc.WithPerRPCCredentials(oauth.TokenSource{
			TokenSource: oauth2.StaticTokenSource(&oauth2.Token{
				AccessToken: token,
			}),
		}),
		grpc.WithUnaryInterceptor(retry.UnaryClientInterceptor(
			retry.WithOnRetryCallback(getGRPCOnRetryCallbackFunc()),
			retry.WithBackoff(retry.BackoffExponentialWithJitterBounded(100*time.Millisecond, 0.75, 2*time.Second)),
			retry.WithCodes(codes.Aborted, codes.Unavailable),
			retry.WithMax(1000), // to provide effectively unlimited retries, with respect to the context deadline
		)),
		// forcefully disable usage of any HTTP proxy - this is needed since on AKS nodes, the no_proxy
		// environment variable will only contain the FQDN of the apiserver rather than its IP address.
		// Without this option, only having the FQDN within no_proxy isn't enough to have the client bypass
		// configured HTTP proxies when communicating with the bootstrap server within the control plane.
		// see: https://github.com/grpc/grpc-go/issues/3401 for more details.
		grpc.WithNoProxy(),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to dial client connection with context: %w", err)
	}

	return akssecuretlsbootstrapv1.NewSecureTLSBootstrapServiceClient(conn), conn.Close, nil
}

func getGRPCOnRetryCallbackFunc() retry.OnRetryCallback {
	// this function is called after every retry attempt assuming the attempt failed,
	// and the failure was not caused by a context error (e.g. DeadlineExceeded or Cancelled),
	// see: https://github.com/grpc-ecosystem/go-grpc-middleware/blob/main/interceptors/retry/retry.go.
	// the error is logged and stored within lastGRPCRetryError.
	return func(ctx context.Context, attempt uint, err error) {
		log.MustGetLogger(ctx).Error("gRPC request failed", zap.Error(err), zap.Uint("attempt", attempt))
		lastGRPCRetryError = err
	}
}

// withLastGRPCRetryErrorIfDeadlineExceeded wraps the error with lastGRPCRetryError if the error
// was caused by a context.DeadlineExceeded.
func withLastGRPCRetryErrorIfDeadlineExceeded(err error) error {
	if lastGRPCRetryError == nil || status.Code(err) != codes.DeadlineExceeded {
		return err
	}
	return fmt.Errorf("%w: last error: %s", err, lastGRPCRetryError)
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
