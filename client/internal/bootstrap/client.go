// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package bootstrap

import (
	"context"
	"encoding/base64"
	"fmt"

	"github.com/Azure/aks-secure-tls-bootstrap/client/internal/imds"
	"github.com/Azure/aks-secure-tls-bootstrap/client/internal/kubeconfig"
	"github.com/Azure/aks-secure-tls-bootstrap/client/internal/log"
	"github.com/Azure/aks-secure-tls-bootstrap/client/internal/telemetry"
	v1 "github.com/Azure/aks-secure-tls-bootstrap/service/pkg/gen/akssecuretlsbootstrap/v1"
	"go.uber.org/zap"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

type Client struct {
	imdsClient             imds.Client
	kubeconfigValidator    kubeconfig.Validator
	getServiceClientFunc   getServiceClientFunc
	extractAccessTokenFunc extractAccessTokenFunc
}

func NewClient(ctx context.Context) (*Client, error) {
	return &Client{
		imdsClient:             imds.NewClient(ctx),
		kubeconfigValidator:    kubeconfig.NewValidator(),
		getServiceClientFunc:   getServiceClient,
		extractAccessTokenFunc: extractAccessToken,
	}, nil
}

func (c *Client) BootstrapKubeletClientCredential(ctx context.Context, cfg *Config) (*clientcmdapi.Config, error) {
	logger := log.MustGetLogger(ctx)

	err := c.validateKubeconfig(ctx, cfg.KubeconfigPath, cfg.EnsureAuthorizedClient)
	if err == nil {
		logger.Info("existing kubeconfig is valid, will skip bootstrapping", zap.String("kubeconfig", cfg.KubeconfigPath))
		return nil, nil
	}
	logger.Info("failed to validate existing kubeconfig, will bootstrap a new client credential", zap.String("kubeconfig", cfg.KubeconfigPath), zap.Error(err))

	token, err := c.getAccessToken(ctx, cfg.CustomClientID, cfg.AADResource, &cfg.ProviderConfig)
	if err != nil {
		logger.Error(err.Error())
		return nil, &BootstrapError{
			errorType: ErrorTypeGetAccessTokenFailure,
			inner:     err,
		}
	}
	logger.Info("generated access token for gRPC connection")

	serviceClient, closer, err := c.getServiceClient(ctx, token, cfg)
	if err != nil {
		logger.Error(err.Error())
		return nil, &BootstrapError{
			errorType: ErrorTypeGetServiceClientFailure,
			inner:     err,
		}
	}
	defer func() {
		if err := closer(); err != nil {
			logger.Error("failed to close gRPC client connection", zap.Error(err))
		}
	}()
	logger.Info("created bootstrap service gRPC client")

	instanceData, err := c.getInstanceData(ctx)
	if err != nil {
		logger.Error(err.Error())
		return nil, &BootstrapError{
			errorType: ErrorTypeGetInstanceDataFailure,
			inner:     err,
		}
	}
	logger.Info("retrieved instance metadata from IMDS", zap.String("resourceId", instanceData.Compute.ResourceID))

	nonce, err := c.getNonce(ctx, serviceClient, &v1.GetNonceRequest{
		ResourceId: instanceData.Compute.ResourceID,
	})
	if err != nil {
		logger.Error(err.Error())
		return nil, &BootstrapError{
			errorType: ErrorTypeGetNonceFailure,
			inner:     err,
		}
	}
	logger.Info("received new nonce from bootstrap server")

	attestedData, err := c.getAttestedData(ctx, nonce)
	if err != nil {
		logger.Error(err.Error())
		return nil, &BootstrapError{
			errorType: ErrorTypeGetAttestedDataFailure,
			inner:     err,
		}
	}
	logger.Info("retrieved instance attested data from IMDS")

	csrPEM, keyPEM, err := c.getCSR(ctx)
	if err != nil {
		logger.Error(err.Error())
		return nil, &BootstrapError{
			errorType: ErrorTypeGetCSRFailure,
			inner:     err,
		}
	}
	logger.Info("generated kubelet client CSR and associated private key")

	certPEM, err := c.getCredential(ctx, serviceClient, &v1.GetCredentialRequest{
		ResourceId:    instanceData.Compute.ResourceID,
		Nonce:         nonce,
		AttestedData:  attestedData.Signature,
		EncodedCsrPem: base64.StdEncoding.EncodeToString(csrPEM),
	})
	if err != nil {
		logger.Error(err.Error())
		return nil, &BootstrapError{
			errorType: ErrorTypeGetCredentialFailure,
			inner:     err,
		}
	}
	logger.Info("received valid kubelet client credential from bootstrap server")

	kubeconfigData, err := c.generateKubeconfig(ctx, certPEM, keyPEM, &kubeconfig.Config{
		APIServerFQDN:     cfg.APIServerFQDN,
		ClusterCAFilePath: cfg.ClusterCAFilePath,
		CertDir:           cfg.CertDir,
	})
	if err != nil {
		logger.Error(err.Error())
		return nil, &BootstrapError{
			errorType: ErrorTypeGenerateKubeconfigFailure,
			inner:     err,
		}
	}
	logger.Info("successfully generated new kubeconfig data")

	return kubeconfigData, nil
}

func (c *Client) validateKubeconfig(ctx context.Context, kubeconfigPath string, ensureAuthorizedClient bool) error {
	endSpan := telemetry.StartSpan(ctx, "ValidateKubeconfig")
	defer endSpan()

	if err := c.kubeconfigValidator.Validate(ctx, kubeconfigPath, ensureAuthorizedClient); err != nil {
		return fmt.Errorf("failed to validate kubeconfig: %w", err)
	}
	return nil
}

func (c *Client) getServiceClient(ctx context.Context, token string, cfg *Config) (v1.SecureTLSBootstrapServiceClient, closeFunc, error) {
	endSpan := telemetry.StartSpan(ctx, "GetServiceClient")
	defer endSpan()

	serviceClient, closer, err := c.getServiceClientFunc(token, cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create bootstrap service client: %w", err)
	}

	return serviceClient, closer, nil
}

func (c *Client) getInstanceData(ctx context.Context) (*imds.VMInstanceData, error) {
	endSpan := telemetry.StartSpan(ctx, "GetInstanceData")
	defer endSpan()

	instanceData, err := c.imdsClient.GetInstanceData(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve instance metadata from IMDS: %w", err)
	}
	return instanceData, nil
}

func (c *Client) getAttestedData(ctx context.Context, nonce string) (*imds.VMAttestedData, error) {
	endSpan := telemetry.StartSpan(ctx, "GetAttestedData")
	defer endSpan()

	attestedData, err := c.imdsClient.GetAttestedData(ctx, nonce)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve instance attested data from IMDS: %w", err)
	}
	return attestedData, nil
}

func (c *Client) getNonce(ctx context.Context, serviceClient v1.SecureTLSBootstrapServiceClient, req *v1.GetNonceRequest) (string, error) {
	endSpan := telemetry.StartSpan(ctx, "GetNonce")
	defer endSpan()

	nonceResponse, err := serviceClient.GetNonce(ctx, req)
	if err != nil {
		err = withLastGRPCRetryErrorIfDeadlineExceeded(err)
		return "", fmt.Errorf("failed to retrieve a nonce from bootstrap server: %w", err)
	}
	return nonceResponse.GetNonce(), nil
}

func (c *Client) getCSR(ctx context.Context) ([]byte, []byte, error) {
	endSpan := telemetry.StartSpan(ctx, "GetCSR")
	defer endSpan()

	csrPEM, keyPEM, err := makeKubeletClientCSR()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create kubelet client CSR: %w", err)
	}
	return csrPEM, keyPEM, nil
}

func (c *Client) getCredential(ctx context.Context, serviceClient v1.SecureTLSBootstrapServiceClient, req *v1.GetCredentialRequest) ([]byte, error) {
	endSpan := telemetry.StartSpan(ctx, "GetCredential")
	defer endSpan()

	credentialResponse, err := serviceClient.GetCredential(ctx, req)
	if err != nil {
		err = withLastGRPCRetryErrorIfDeadlineExceeded(err)
		return nil, fmt.Errorf("failed to retrieve new kubelet client credential from bootstrap server: %w", err)
	}

	encodedCertPEM := credentialResponse.GetEncodedCertPem()
	if encodedCertPEM == "" {
		return nil, fmt.Errorf("cert data from bootstrap server is empty")
	}
	certPEM, err := base64.StdEncoding.DecodeString(encodedCertPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to decode cert data from bootstrap server: %w", err)
	}
	return certPEM, nil
}

func (c *Client) generateKubeconfig(ctx context.Context, certPEM, keyPEM []byte, cfg *kubeconfig.Config) (*clientcmdapi.Config, error) {
	endSpan := telemetry.StartSpan(ctx, "GenerateKubeconfig")
	defer endSpan()

	kubeconfigData, err := kubeconfig.GenerateForCertAndKey(certPEM, keyPEM, cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to generate kubeconfig for new client cert and key: %w", err)
	}
	return kubeconfigData, nil
}
