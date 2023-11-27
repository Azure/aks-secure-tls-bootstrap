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
	"go.uber.org/zap"
	"golang.org/x/oauth2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/oauth"
)

// TLSBootstrapClient retrieves tokens for performing node TLS bootstrapping.
type TLSBootstrapClient interface {
	GetCredential(ctx context.Context) (string, error)
}

func NewTLSBootstrapClient(logger *zap.Logger, opts SecureTLSBootstrapClientOpts) TLSBootstrapClient {
	reader := newOSFileReader()
	imdsClient := NewImdsClient(logger)
	aadClient := NewAadClient(reader, logger)
	pbClient := pb.NewAKSBootstrapTokenRequestClient()

	return &tlsBootstrapClientImpl{
		reader:         reader,
		logger:         logger,
		imdsClient:     imdsClient,
		pbClient:       pbClient,
		aadClient:      aadClient,
		customClientID: opts.CustomClientID,
		nextProto:      opts.NextProto,
		resource:       opts.AADResource,
	}
}

type tlsBootstrapClientImpl struct {
	logger         *zap.Logger
	azureConfig    *datamodel.AzureConfig
	imdsClient     ImdsClient
	aadClient      AadClient
	reader         fileReader
	pbClient       pb.AKSBootstrapTokenRequestClient
	customClientID string
	nextProto      string
	resource       string
}

func (c *tlsBootstrapClientImpl) setupClientConnection(ctx context.Context, execCredential *datamodel.ExecCredential) (*grpc.ClientConn, error) {
	c.logger.Info("setting up GRPC connection with bootstrap server...")

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

	c.logger.Debug("generating JWT token for auth...")

	token, err := c.getAuthToken(ctx, c.customClientID, c.resource, c.azureConfig)
	if err != nil {
		return nil, err
	}
	c.logger.Info("generated JWT token for auth")

	c.logger.Debug("extracting server URL from exec credential...")
	serverURL, err := getServerURL(execCredential)
	if err != nil {
		return nil, err
	}
	c.logger.Info("extracted server URL from exec credential")

	c.logger.Debug("dialing TLS bootstrap server and creating GRPC connection...")
	conn, err := grpc.DialContext(
		ctx, serverURL,
		grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)),
		grpc.WithPerRPCCredentials(oauth.TokenSource{
			TokenSource: oauth2.StaticTokenSource(&oauth2.Token{
				AccessToken: token,
			}),
		}),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to dial client connection with context: %w", err)
	}
	c.logger.Info("dialed TLS bootstrap server and created GRPC connection")

	return conn, nil
}

func (c *tlsBootstrapClientImpl) GetCredential(ctx context.Context) (string, error) {
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

	conn, err := c.setupClientConnection(ctx, execCredential)
	if err != nil {
		return "", fmt.Errorf("unable to setup GRPC client connection to TLS bootstrap server: %w", err)
	}
	defer conn.Close()
	c.pbClient.SetGRPCConnection(conn)

	c.logger.Debug("retrieving IMDS instance data...")
	instanceData, err := c.imdsClient.GetInstanceData(ctx, baseImdsURL)
	if err != nil {
		return "", fmt.Errorf("failed to retrieve instance metadata from IMDS: %w", err)
	}
	c.logger.Info("retrieved IMDS instance data", zap.String("vmResourceId", instanceData.Compute.ResourceID))

	c.logger.Debug("retrieving nonce from TLS bootstrap token server...")

	nonceRequest := &pb.NonceRequest{ResourceId: instanceData.Compute.ResourceID}
	nonceResponse, err := c.pbClient.GetNonce(ctx, nonceRequest)
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

	c.logger.Debug("retrieving credential from TLS bootstrap server...")

	credentialRequest := &pb.CredentialRequest{
		ResourceId:   instanceData.Compute.ResourceID,
		Nonce:        nonce,
		AttestedData: attestedData.Signature,
	}
	credentialResponse, err := c.pbClient.GetCredential(ctx, credentialRequest)

	if err != nil {
		return "", fmt.Errorf("failed to retrieve a credential from the bootstrap server: %w", err)
	}
	c.logger.Info("received new credential from TLS bootstrap server")

	c.logger.Debug("decoding cert and key from credential response")
	certData, err := base64.StdEncoding.DecodeString(credentialResponse.GetCertificateData())
	if err != nil {
		return "", fmt.Errorf("unable to decode cert data within credential response: %w", err)
	}
	keyData, err := base64.StdEncoding.DecodeString(credentialResponse.GetKeyData())
	if err != nil {
		return "", fmt.Errorf("unable to decode key data within credential response: %w", err)
	}
	c.logger.Info("decoded cert and key from credential response")

	c.logger.Debug("generating new exec credential with cert/key data...")
	newExecCredential, err := getExecCredentialWithData(string(certData), string(keyData))
	if err != nil {
		return "", fmt.Errorf("unable to generate new exec credential with cert/key data: %w", err)
	}
	c.logger.Info("generated new exec credential with cert/key data")

	execCredentialBytes, err := json.Marshal(newExecCredential)
	if err != nil {
		return "", fmt.Errorf("failed to marshal execCredential")
	}

	return string(execCredentialBytes), nil
}

func getExecCredentialWithData(certData, keyData string) (*datamodel.ExecCredential, error) {
	if certData == "" {
		return nil, fmt.Errorf("cert data is empty, cannot generate exec credential")
	}
	if keyData == "" {
		return nil, fmt.Errorf("key data is empty, cannot generate exec credential")
	}
	return &datamodel.ExecCredential{
		APIVersion: "client.authentication.k8s.io/v1",
		Kind:       "ExecCredential",
		Status: datamodel.ExecCredentialStatus{
			ClientCertificateData: certData,
			ClientKeyData:         keyData,
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

	//nolint: gosec // let server dictate TLS version
	tlsConfig := &tls.Config{
		RootCAs:            tlsRootStore,
		InsecureSkipVerify: insecureSkipVerify,
	}
	if nextProto != "" {
		tlsConfig.NextProtos = []string{nextProto, "h2"}
	}

	return tlsConfig, nil
}
