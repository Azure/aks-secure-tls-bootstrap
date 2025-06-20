// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package bootstrap

import (
	"context"
	"encoding/base64"
	"fmt"

	"github.com/Azure/aks-secure-tls-bootstrap/client/internal/imds"
	"github.com/Azure/aks-secure-tls-bootstrap/client/internal/kubeconfig"
	"github.com/Azure/aks-secure-tls-bootstrap/client/internal/telemetry"
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

func (c *Client) BootstrapKubeletClientCredential(ctx context.Context, cfg *Config) (*clientcmdapi.Config, error) {
	err := c.kubeconfigValidator.Validate(ctx, cfg.KubeconfigPath, cfg.EnsureAuthorizedClient)
	if err == nil {
		c.logger.Info("existing kubeconfig is valid, will skip bootstrapping", zap.String("kubeconfig", cfg.KubeconfigPath))
		return nil, nil
	}
	c.logger.Info("failed to validate existing kubeconfig, will bootstrap a new client credential", zap.String("kubeconfig", cfg.KubeconfigPath), zap.Error(err))

	token, err := c.getAccessToken(ctx, cfg.CustomClientID, cfg.AADResource, &cfg.ProviderConfig)
	if err != nil {
		c.logger.Error("failed to generate access token for gRPC connection", zap.Error(err))
		return nil, &BootstrapError{
			errorType: ErrorTypeGetAccessTokenFailure,
			inner:     fmt.Errorf("failed to generate access token for gRPC connection: %w", err),
		}
	}
	c.logger.Info("generated access token for gRPC connection")

	serviceClient, close, err := c.getServiceClientFunc(ctx, token, cfg)
	if err != nil {
		c.logger.Error("failed to setup bootstrap service connection", zap.Error(err))
		return nil, &BootstrapError{
			errorType: ErrorTypeGetServiceClientFailure,
			inner:     fmt.Errorf("failed to setup bootstrap service connection: %w", err),
		}
	}
	defer func() {
		if err := close(); err != nil {
			c.logger.Error("failed to close gRPC client connection", zap.Error(err))
		}
	}()
	c.logger.Info("created gRPC connection and bootstrap service client")

	instanceData, err := c.imdsClient.GetInstanceData(ctx)
	if err != nil {
		c.logger.Error("failed to retrieve instance metadata from IMDS", zap.Error(err))
		return nil, &BootstrapError{
			errorType: ErrorTypeGetInstanceDataFailure,
			inner:     fmt.Errorf("failed to retrieve instance metadata from IMDS: %w", err),
		}
	}
	c.logger.Info("retrieved IMDS instance data", zap.String("vmResourceId", instanceData.Compute.ResourceID))

	nonce, err := c.getNonce(ctx, serviceClient, instanceData)
	if err != nil {
		return nil, err
	}

	attestedData, err := c.imdsClient.GetAttestedData(ctx, nonce)
	if err != nil {
		c.logger.Error("failed to retrieve attested data from IMDS", zap.Error(err))
		return nil, &BootstrapError{
			errorType: ErrorTypeGetAttestedDataFailure,
			inner:     fmt.Errorf("failed to retrieve attested data from IMDS: %w", err),
		}
	}
	c.logger.Info("retrieved IMDS attested data")

	csrPEM, keyPEM, err := makeKubeletClientCSR(ctx)
	if err != nil {
		c.logger.Error("failed to create kubelet client CSR", zap.Error(err))
		return nil, &BootstrapError{
			errorType: ErrorTypeMakeKubeletClientCSRFailure,
			inner:     fmt.Errorf("failed to create kubelet client CSR: %w", err),
		}
	}
	c.logger.Info("generated kubelet client CSR and associated private key")

	certPEM, err := c.getCredential(ctx, serviceClient, instanceData, attestedData, nonce, csrPEM)
	if err != nil {
		return nil, err
	}

	kubeconfigData, err := kubeconfig.GenerateForCertAndKey(ctx, certPEM, keyPEM, &kubeconfig.Config{
		APIServerFQDN:     cfg.APIServerFQDN,
		ClusterCAFilePath: cfg.ClusterCAFilePath,
		CredFilePath:      cfg.CredFilePath,
	})
	if err != nil {
		c.logger.Error("failed to generate kubeconfig for new client cert and key", zap.Error(err))
		return nil, &BootstrapError{
			errorType: ErrorTypeGenerateKubeconfigFailure,
			inner:     fmt.Errorf("failed to generate kubeconfig for new client cert and key: %w", err),
		}
	}
	c.logger.Info("successfully generated new kubeconfig data")

	return kubeconfigData, nil
}

func (c *Client) getNonce(ctx context.Context, serviceClient akssecuretlsbootstrapv1.SecureTLSBootstrapServiceClient, instanceData *imds.VMInstanceData) (string, error) {
	recorder := telemetry.MustGetTaskRecorder(ctx)
	recorder.Start("GetNonce")
	defer recorder.Stop("GetNonce")

	nonceResponse, err := serviceClient.GetNonce(ctx, &akssecuretlsbootstrapv1.GetNonceRequest{
		ResourceId: instanceData.Compute.ResourceID,
	})
	if err != nil {
		c.logger.Error("failed retrieve a nonce from bootstrap server", zap.Error(err))
		return "", &BootstrapError{
			errorType: ErrorTypeGetNonceFailure,
			inner:     fmt.Errorf("failed to retrieve a nonce from bootstrap server: %w", err),
		}
	}
	c.logger.Info("received new nonce from bootstrap server")
	return nonceResponse.GetNonce(), nil
}

func (c *Client) getCredential(
	ctx context.Context,
	serviceClient akssecuretlsbootstrapv1.SecureTLSBootstrapServiceClient,
	instanceData *imds.VMInstanceData,
	attestedData *imds.VMAttestedData,
	nonce string,
	csrPEM []byte) ([]byte, error) {
	recorder := telemetry.MustGetTaskRecorder(ctx)
	recorder.Start("GetCredential")
	defer recorder.Stop("GetCredential")

	credentialResponse, err := serviceClient.GetCredential(ctx, &akssecuretlsbootstrapv1.GetCredentialRequest{
		ResourceId:    instanceData.Compute.ResourceID,
		Nonce:         nonce,
		AttestedData:  attestedData.Signature,
		EncodedCsrPem: base64.StdEncoding.EncodeToString(csrPEM),
	})
	if err != nil {
		c.logger.Error("failed to retrieve new kubelet client credential from bootstrap server", zap.Error(err))
		return nil, &BootstrapError{
			errorType: ErrorTypeGetCredentialFailure,
			inner:     fmt.Errorf("failed to retrieve new kubelet client credential from bootstrap server: %w", err),
		}
	}
	c.logger.Info("received kubelet client credential from bootstrap server")

	encodedCertPEM := credentialResponse.GetEncodedCertPem()
	if encodedCertPEM == "" {
		c.logger.Error("cert data from bootstrap server is empty")
		return nil, &BootstrapError{
			errorType: ErrorTypeGetCredentialFailure,
			inner:     fmt.Errorf("cert data from bootstrap server is empty"),
		}
	}
	certPEM, err := base64.StdEncoding.DecodeString(encodedCertPEM)
	if err != nil {
		c.logger.Error("failed to decode cert data from bootstrap server", zap.Error(err))
		return nil, &BootstrapError{
			errorType: ErrorTypeGetCredentialFailure,
			inner:     fmt.Errorf("failed to decode cert data from bootstrap server: %w", err),
		}
	}

	return certPEM, nil
}
