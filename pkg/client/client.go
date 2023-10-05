// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"os"

	"github.com/Azure/aks-tls-bootstrap-client/pkg/datamodel"
	pb "github.com/Azure/aks-tls-bootstrap-client/pkg/protos"
	"github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/oauth"
)

// TLSBootstrapClient retrieves tokens for performing node TLS bootstrapping.
type TLSBootstrapClient interface {
	GetBootstrapToken(ctx context.Context) (string, error)
}

func NewTLSBootstrapClient(logger *logrus.Logger, clientID, nextProto string) TLSBootstrapClient {
	imdsClient := NewImdsClient(logger)
	aadClient := NewAadClient(logger)

	return &tlsBootstrapClientImpl{
		logger:     logger,
		imdsClient: imdsClient,
		aadClient:  aadClient,
		clientID:   clientID,
		nextProto:  nextProto,
	}
}

type tlsBootstrapClientImpl struct {
	logger     *logrus.Logger
	imdsClient ImdsClient
	aadClient  AadClient
	clientID   string
	nextProto  string
}

func (c *tlsBootstrapClientImpl) setupClientConnection(ctx context.Context) (*grpc.ClientConn, error) {
	c.logger.Debug("loading exec credential...")
	execCredential, err := loadExecCredential()
	if err != nil {
		return nil, err
	}
	c.logger.Info("exec credential successfully loaded")

	c.logger.Debug("decoding cluster CA data...")
	pemCAs, err := base64.StdEncoding.DecodeString(execCredential.Spec.Cluster.CertificateAuthorityData)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64 cluster certificates: %w", err)
	}
	c.logger.Info("decoded cluster CA data")

	c.logger.Debug("generating TLS config for GRPC client connection...")
	tlsConfig, err := getTLSConfig(pemCAs, c.nextProto, execCredential.Spec.Cluster.InsecureSkipTLSVerify)
	if err != nil {
		return nil, fmt.Errorf("failed to get TLS config: %w", err)
	}
	c.logger.Info("generated TLS config for GRPC client connection")

	c.logger.Debug("loading azure.json...")
	azureConfig, err := loadAzureJSON()
	if err != nil {
		return nil, fmt.Errorf("failed to parse azure config from azure.json: %w", err)
	}
	c.logger.Info("loaded azure.json")

	c.logger.Debug("generating JWT token for auth...")
	token, err := c.getAuthToken(ctx, c.clientID, azureConfig)
	if err != nil {
		return nil, err
	}
	c.logger.Info("generated JWT token for auth")

	c.logger.Debug("extracting server URL from exec credential...")
	server, err := getServerURL(execCredential)
	if err != nil {
		return nil, err
	}
	c.logger.Info("extracted server URL from exec credential")

	c.logger.Debug("dialing TLS bootstrap server and creating GRPC connection...")
	conn, err := grpc.DialContext(
		ctx, server,
		grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)),
		grpc.WithPerRPCCredentials(oauth.TokenSource{
			TokenSource: oauth2.StaticTokenSource(&oauth2.Token{
				AccessToken: token,
			}),
		}),
	)
	c.logger.Info("dialed TLS bootstrap server and created GRPC connection")

	return conn, nil
}

func (c *tlsBootstrapClientImpl) GetBootstrapToken(ctx context.Context) (string, error) {
	conn, err := c.setupClientConnection(ctx)
	if err != nil {
		return "", fmt.Errorf("unable to setup GRPC client connection to TLS bootstrap server: %w", err)
	}
	defer conn.Close()

	pbClient := pb.NewAKSBootstrapTokenRequestClient(conn)

	c.logger.Debug("retrieving IMDS instance data...")
	instanceData, err := c.imdsClient.GetInstanceData(ctx, baseImdsURL)
	if err != nil {
		return "", fmt.Errorf("failed to retrieve instance metadata from IMDS: %w", err)
	}
	c.logger.WithField("vmResourceId", instanceData.Compute.ResourceID).Info("retrieved IMDS instance data")

	c.logger.Debug("retrieving nonce from TLS bootstrap token server...")
	nonceResponse, err := pbClient.GetNonce(ctx, &pb.NonceRequest{
		ResourceId: instanceData.Compute.ResourceID,
	})
	if err != nil {
		return "", fmt.Errorf("failed to retrieve a nonce: %w", err)
	}
	c.logger.Info("received new nonce from TLS bootstrap server")
	nonce := nonceResponse.GetNonce()

	c.logger.Debug("retrieving IMDS attested data...")
	attestedData, err := c.imdsClient.GetAttestedData(ctx, baseImdsURL, nonce)
	if err != nil {
		return "", fmt.Errorf("failed to retrieve attested data from IMDS: %w", err)
	}
	c.logger.Info("retrieved IMDS attested data")

	c.logger.Debug("retrieving bootstrap token from TLS bootstrap server...")
	tokenResponse, err := pbClient.GetToken(ctx, &pb.TokenRequest{
		ResourceId:   instanceData.Compute.ResourceID,
		Nonce:        nonce,
		AttestedData: attestedData.Signature,
	})
	if err != nil {
		return "", fmt.Errorf("failed to retrieve a token: %w", err)
	}
	c.logger.Info("received new bootstrap token from TLS bootstrap server")

	c.logger.Debug("generating new exec credential with bootstrap token...")
	execCredentialWithToken, err := getExecCredentialWithToken(tokenResponse.GetToken(), tokenResponse.GetExpiration())
	if err != nil {
		return "", fmt.Errorf("unable to generate new exec credential with bootstrap token: %w", err)
	}
	c.logger.Info("generated new exec credential with bootstrap token")

	execCredentialBytes, err := json.Marshal(execCredentialWithToken)
	if err != nil {
		return "", fmt.Errorf("failed to marshal execCredential")
	}

	return string(execCredentialBytes), nil
}

func getExecCredentialWithToken(token, expirationTimestamp string) (*datamodel.ExecCredential, error) {
	if token == "" {
		return nil, fmt.Errorf("token string is empty, cannot generate exec credential")
	}
	if expirationTimestamp == "" {
		return nil, fmt.Errorf("token expiration timestamp is empty, cannot generate exec credential")
	}
	return &datamodel.ExecCredential{
		APIVersion: "client.authentication.k8s.io/v1",
		Kind:       "ExecCredential",
		Status: datamodel.ExecCredentialStatus{
			Token:               token,
			ExpirationTimestamp: expirationTimestamp,
		},
	}, nil
}

func loadExecCredential() (*datamodel.ExecCredential, error) {
	execInfo := os.Getenv(kubernetesExecInfoVarName)
	if execInfo == "" {
		return nil, fmt.Errorf("%s must be set to retrieve bootstrap token", kubernetesExecInfoVarName)
	}
	var execCredential datamodel.ExecCredential
	if err := json.Unmarshal([]byte(execInfo), &execCredential); err != nil {
		return nil, err
	}
	return &execCredential, nil
}

func getServerURL(execCredential *datamodel.ExecCredential) (string, error) {
	serverURL, err := url.Parse(execCredential.Spec.Cluster.Server)
	if err != nil {
		return "", fmt.Errorf("failed to parse server URL: %w", err)
	}
	server := serverURL.Hostname() + ":" + serverURL.Port()
	return server, nil
}

func getTLSConfig(pemCAs []byte, nextProto string, insecureSkipVerify bool) (*tls.Config, error) {
	tlsRootStore := x509.NewCertPool()
	ok := tlsRootStore.AppendCertsFromPEM(pemCAs)
	if !ok {
		return nil, fmt.Errorf("failed to load cluster root CA(s)")
	}

	//nolint: gosec // ignore tls min version for now
	tlsConfig := &tls.Config{
		RootCAs: tlsRootStore,
		// TODO(cameissner): fix me
		// MinVersion: tls.VersionTLS13,
		InsecureSkipVerify: insecureSkipVerify,
	}
	if nextProto != "" {
		tlsConfig.NextProtos = []string{nextProto, "h2"}
	}

	return tlsConfig, nil
}
