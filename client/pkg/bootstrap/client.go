// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package bootstrap

import (
	"context"
	"encoding/base64"
	"fmt"

	"github.com/Azure/aks-secure-tls-bootstrap/client/pkg/aad"
	"github.com/Azure/aks-secure-tls-bootstrap/client/pkg/imds"
	"github.com/Azure/aks-secure-tls-bootstrap/client/pkg/kubeconfig"
	secureTLSBootstrapService "github.com/Azure/aks-secure-tls-bootstrap/service/protos"
	"go.uber.org/zap"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

type Client struct {
	logger               *zap.Logger
	serviceClientFactory serviceClientFactoryFunc
	imdsClient           imds.Client
	aadClient            aad.Client
	kubeconfigValidator  kubeconfig.Validator
}

func NewClient(logger *zap.Logger) (*Client, error) {
	return &Client{
		logger:               logger,
		serviceClientFactory: secureTLSBootstrapServiceClientFactory,
		imdsClient:           imds.NewClient(logger),
		aadClient:            aad.NewClient(logger),
		kubeconfigValidator:  kubeconfig.NewValidator(),
	}, nil
}

func (c *Client) GetKubeletClientCredential(ctx context.Context, cfg *Config) (*clientcmdapi.Config, error) {
	err := c.kubeconfigValidator.Validate(cfg.KubeconfigPath, cfg.EnsureAuthorizedClient)
	if err == nil {
		c.logger.Info("existing kubeconfig is valid, exiting without bootstrapping")
		return nil, nil
	}
	c.logger.Info("failed to validate existing kubeconfig, will continue to bootstrap", zap.String("kubeconfig", cfg.KubeconfigPath), zap.Error(err))

	authToken, err := c.getAuthToken(ctx, cfg.CustomClientID, cfg.AADResource, cfg.AzureConfig)
	if err != nil {
		c.logger.Error("failed to generate JWT for GRPC connection", zap.Error(err))
		return nil, fmt.Errorf("failed to generate JWT for GRPC connection: %w", err)
	}
	c.logger.Info("generated JWT for auth")

	serviceClient, conn, err := c.serviceClientFactory(ctx, c.logger, &serviceClientFactoryConfig{
		fqdn:                  cfg.APIServerFQDN,
		clusterCAFilePath:     cfg.ClusterCAFilePath,
		insecureSkipTLSVerify: cfg.InsecureSkipTLSVerify,
		nextProto:             cfg.NextProto,
		authToken:             authToken,
	})
	if err != nil {
		c.logger.Error("failed to setup bootstrap service connection", zap.Error(err))
		return nil, fmt.Errorf("failed to setup bootstrap service connection: %w", err)
	}
	if conn != nil {
		// conn should be non-nil if there's no error, though we need this to handle
		// cases created by unit tests
		defer conn.Close()
	}
	c.logger.Info("created GRPC connection and bootstrap service client")

	instanceData, err := c.imdsClient.GetInstanceData(ctx)
	if err != nil {
		c.logger.Error("failed to retrieve instance metadata from IMDS", zap.Error(err))
		return nil, fmt.Errorf("failed to retrieve instance metadata from IMDS: %w", err)
	}
	c.logger.Info("retrieved IMDS instance data", zap.String("vmResourceId", instanceData.Compute.ResourceID))

	nonceResponse, err := serviceClient.GetNonce(ctx, &secureTLSBootstrapService.NonceRequest{
		ResourceID: instanceData.Compute.ResourceID,
	})
	if err != nil {
		c.logger.Error("failed retrieve a nonce from bootstrap server", zap.Error(err))
		return nil, fmt.Errorf("failed to retrieve a nonce from bootstrap server: %w", err)
	}
	c.logger.Info("received new nonce from bootstrap server")
	nonce := nonceResponse.GetNonce()

	attestedData, err := c.imdsClient.GetAttestedData(ctx, nonce)
	if err != nil {
		c.logger.Error("failed to retrieve attested data from IMDS", zap.Error(err))
		return nil, fmt.Errorf("failed to retrieve attested data from IMDS: %w", err)
	}
	c.logger.Info("retrieved IMDS attested data")

	csrPEM, privateKey, err := makeKubeletClientCSR()
	if err != nil {
		c.logger.Error("failed to create kubelet client CSR", zap.Error(err))
		return nil, fmt.Errorf("failed to create kubelet client CSR: %w", err)
	}
	c.logger.Info("generated kubelet client CSR and associated private key")

	credentialResponse, err := serviceClient.GetCredential(ctx, &secureTLSBootstrapService.CredentialRequest{
		ResourceID:    instanceData.Compute.ResourceID,
		Nonce:         nonce,
		AttestedData:  attestedData.Signature,
		EncodedCSRPEM: base64.StdEncoding.EncodeToString(csrPEM),
	})
	if err != nil {
		c.logger.Error("failed to retrieve new kubelet client credential from bootstrap server", zap.Error(err))
		return nil, fmt.Errorf("failed to retrieve new kubelet client credential from bootstrap server: %w", err)
	}
	c.logger.Info("received kubelet client credential from bootstrap server")

	encodedCertPEM := credentialResponse.GetEncodedCertPEM()
	if encodedCertPEM == "" {
		c.logger.Error("cert data from bootstrap server is empty")
		return nil, fmt.Errorf("cert data from bootstrap server is empty")
	}
	certPEM, err := base64.StdEncoding.DecodeString(encodedCertPEM)
	if err != nil {
		c.logger.Error("failed to decode cert data from bootstrap server", zap.Error(err))
		return nil, fmt.Errorf("failed to decode cert data from bootstrap server: %w", err)
	}
	kubeconfigData, err := kubeconfig.GenerateForCertAndKey(certPEM, privateKey, &kubeconfig.Config{
		APIServerFQDN:     cfg.APIServerFQDN,
		ClusterCAFilePath: cfg.ClusterCAFilePath,
		CertFilePath:      cfg.CertFilePath,
		KeyFilePath:       cfg.KeyFilePath,
	})
	if err != nil {
		c.logger.Error("failed to generate kubeconfig for new client cert and key", zap.Error(err))
		return nil, fmt.Errorf("failed to generate kubeconfig for new client cert and key: %w", err)
	}
	c.logger.Info("successfully generated new kubeconfig data")

	return kubeconfigData, nil
}
