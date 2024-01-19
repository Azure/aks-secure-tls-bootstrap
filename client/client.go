// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/url"
	"os"

	"github.com/Azure/aks-secure-tls-bootstrap/client/pkg/datamodel"
	secureTLSBootstrapService "github.com/Azure/aks-tls-bootstrap-client/service/protos"
	"go.uber.org/zap"
)

// TLSBootstrapClient retrieves tokens for performing node TLS bootstrapping.
type TLSBootstrapClient interface {
	GetBootstrapToken(ctx context.Context) (string, error)
}

type tlsBootstrapClientImpl struct {
	reader fileReader
	logger *zap.Logger

	serviceClientFactory serviceClientFactory

	imdsClient  ImdsClient
	aadClient   AadClient
	azureConfig *datamodel.AzureConfig

	customClientID string
	nextProto      string
	resource       string
}

func NewTLSBootstrapClient(logger *zap.Logger, opts SecureTLSBootstrapClientOpts) TLSBootstrapClient {
	reader := newOSFileReader()
	imdsClient := NewImdsClient(logger)
	aadClient := NewAadClient(reader, logger)

	return &tlsBootstrapClientImpl{
		reader:               reader,
		logger:               logger,
		serviceClientFactory: secureTLSBootstrapServiceClientFactory,
		imdsClient:           imdsClient,
		aadClient:            aadClient,
		customClientID:       opts.CustomClientID,
		nextProto:            opts.NextProto,
		resource:             opts.AADResource,
	}
}

func (c *tlsBootstrapClientImpl) GetBootstrapToken(ctx context.Context) (string, error) {
	c.logger.Debug("loading exec credential...")
	execCredential, err := loadExecCredential()
	if err != nil {
		return "", err
	}
	c.logger.Info("loaded kubernetes exec credential")

	c.logger.Debug("loading azure config...")
	if err = c.loadAzureConfig(); err != nil {
		return "", fmt.Errorf("failed to parse azure config: %w", err)
	}
	c.logger.Info("loaded azure config")

	c.logger.Debug("generating JWT token for auth...")
	authToken, err := c.getAuthToken(ctx, c.customClientID, c.resource, c.azureConfig)
	if err != nil {
		return "", err
	}
	c.logger.Info("generated JWT token for auth")

	c.logger.Debug("creating GRPC connection and bootstrap service client...")
	serviceClient, conn, err := c.serviceClientFactory(ctx, c.logger, serviceClientFactoryOpts{
		execCredential: execCredential,
		nextProto:      c.nextProto,
		authToken:      authToken,
	})
	if err != nil {
		return "", err
	}
	defer conn.Close()
	c.logger.Info("created GRPC connection and bootstrap service client")

	c.logger.Debug("retrieving IMDS instance data...")
	instanceData, err := c.imdsClient.GetInstanceData(ctx, baseImdsURL)
	if err != nil {
		return "", fmt.Errorf("failed to retrieve instance metadata from IMDS: %w", err)
	}
	c.logger.Info("retrieved IMDS instance data", zap.String("vmResourceId", instanceData.Compute.ResourceID))

	c.logger.Debug("retrieving nonce from TLS bootstrap token server...")
	nonceRequest := &secureTLSBootstrapService.NonceRequest{ResourceID: instanceData.Compute.ResourceID}
	nonceResponse, err := serviceClient.GetNonce(ctx, nonceRequest)
	if err != nil {
		return "", fmt.Errorf("failed to retrieve a nonce from bootstrap server: %w", err)
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

	tokenRequest := &secureTLSBootstrapService.TokenRequest{
		ResourceId:   instanceData.Compute.ResourceID,
		Nonce:        nonce,
		AttestedData: attestedData.Signature,
	}
	tokenResponse, err := serviceClient.GetToken(ctx, tokenRequest)

	if err != nil {
		return "", fmt.Errorf("failed to retrieve a new TLS bootstrap token from the bootstrap server: %w", err)
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
		return nil, fmt.Errorf("unable to parse KUBERNETES_EXEC_INFO data: %w", err)
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
