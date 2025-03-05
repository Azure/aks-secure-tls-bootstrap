// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package bootstrap

import (
	"context"
	"encoding/base64"
	"fmt"

	"github.com/Azure/aks-secure-tls-bootstrap/client/internal/imds"
	"github.com/Azure/aks-secure-tls-bootstrap/client/internal/kubeconfig"
	akssecuretlsbootstrapv1 "github.com/Azure/aks-secure-tls-bootstrap/service/pkg/gen/akssecuretlsbootstrap/v1"
	"go.uber.org/zap"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

type Client struct {
	logger                 *zap.Logger
	imdsClient             imds.Client
	kubeconfigValidator    kubeconfig.Validator
	getServiceClientFunc   getServiceClientFunc
	extractAccessTokenFunc extractAccessTokenFunc
}

func NewClient(logger *zap.Logger) (*Client, error) {
	return &Client{
		logger:                 logger,
		imdsClient:             imds.NewClient(logger),
		kubeconfigValidator:    kubeconfig.NewValidator(logger),
		getServiceClientFunc:   getServiceClient,
		extractAccessTokenFunc: extractAccessToken,
	}, nil
}

func (c *Client) GetKubeletClientCredential(ctx context.Context, config *Config) (*clientcmdapi.Config, error) {
	err := c.kubeconfigValidator.Validate(config.KubeconfigPath, config.EnsureAuthorizedClient)
	if err == nil {
		c.logger.Info("existing kubeconfig is valid, will skip bootstrapping", zap.String("kubeconfig", config.KubeconfigPath))
		return nil, nil
	}
	c.logger.Info("failed to validate existing kubeconfig, will bootstrap a new client credential", zap.String("kubeconfig", config.KubeconfigPath), zap.Error(err))

	token, err := c.getAccessToken(config.CustomClientID, config.AADResource, &config.AzureConfig)
	if err != nil {
		c.logger.Error("failed to generate access token for gRPC connection", zap.Error(err))
		return nil, fmt.Errorf("failed to generate access token for gRPC connection: %w", err)
	}
	c.logger.Info("generated access token for gRPC connection")

	serviceClient, closer, err := c.getServiceClientFunc(token, config)
	if err != nil {
		c.logger.Error("failed to setup bootstrap service connection", zap.Error(err))
		return nil, fmt.Errorf("failed to setup bootstrap service connection: %w", err)
	}
	defer closer.close(c.logger)

	c.logger.Info("created gRPC connection and bootstrap service client")

	instanceData, err := c.imdsClient.GetInstanceData(ctx)
	if err != nil {
		c.logger.Error("failed to retrieve instance metadata from IMDS", zap.Error(err))
		return nil, fmt.Errorf("failed to retrieve instance metadata from IMDS: %w", err)
	}
	c.logger.Info("retrieved IMDS instance data", zap.String("vmResourceId", instanceData.Compute.ResourceID))

	nonceResponse, err := serviceClient.GetNonce(ctx, &akssecuretlsbootstrapv1.GetNonceRequest{
		ResourceId: instanceData.Compute.ResourceID,
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

	credentialResponse, err := serviceClient.GetCredential(ctx, &akssecuretlsbootstrapv1.GetCredentialRequest{
		ResourceId:    instanceData.Compute.ResourceID,
		Nonce:         nonce,
		AttestedData:  attestedData.Signature,
		EncodedCsrPem: base64.StdEncoding.EncodeToString(csrPEM),
	})
	if err != nil {
		c.logger.Error("failed to retrieve new kubelet client credential from bootstrap server", zap.Error(err))
		return nil, fmt.Errorf("failed to retrieve new kubelet client credential from bootstrap server: %w", err)
	}
	c.logger.Info("received kubelet client credential from bootstrap server")

	encodedCertPEM := credentialResponse.GetEncodedCertPem()
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
		APIServerFQDN:     config.APIServerFQDN,
		ClusterCAFilePath: config.ClusterCAFilePath,
		CertFilePath:      config.CertFilePath,
		KeyFilePath:       config.KeyFilePath,
	})
	if err != nil {
		c.logger.Error("failed to generate kubeconfig for new client cert and key", zap.Error(err))
		return nil, fmt.Errorf("failed to generate kubeconfig for new client cert and key: %w", err)
	}
	c.logger.Info("successfully generated new kubeconfig data")

	return kubeconfigData, nil
}
