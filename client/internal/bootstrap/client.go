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

type client struct {
	kubeconfigValidator    kubeconfig.Validator
	imdsClient             imds.Client
	getServiceClientFunc   getServiceClientFunc
	extractAccessTokenFunc extractAccessTokenFunc
}

func newClient(ctx context.Context) *client {
	return &client{
		kubeconfigValidator:    kubeconfig.NewValidator(),
		imdsClient:             imds.NewClient(ctx),
		getServiceClientFunc:   getServiceClient,
		extractAccessTokenFunc: extractAccessToken,
	}
}

func (c *client) bootstrap(ctx context.Context, config *Config) (*clientcmdapi.Config, error) {
	logger := log.MustGetLogger(ctx)

	err := c.validateKubeConfig(ctx, config)
	if err == nil {
		logger.Info("existing kubeconfig is valid, nothing to bootstrap", zap.String("kubeconfig", config.KubeconfigPath))
		return nil, nil
	}
	logger.Info("failed to validate existing kubeconfig, will bootstrap a new kubelet client credential", zap.String("kubeconfig", config.KubeconfigPath), zap.Error(err))

	token, err := c.getAccessToken(ctx, config)
	if err != nil {
		logger.Error(err.Error())
		return nil, &bootstrapError{
			errorType: ErrorTypeGetAccessTokenFailure,
			inner:     err,
		}
	}
	logger.Info("generated access token for gRPC client connection")

	serviceClient, closer, err := c.getServiceClient(ctx, token, config)
	if err != nil {
		logger.Error(err.Error())
		return nil, &bootstrapError{
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

	instanceData, err := c.getInstanceData(ctx, config)
	if err != nil {
		logger.Error(err.Error())
		return nil, &bootstrapError{
			errorType: ErrorTypeGetInstanceDataFailure,
			inner:     err,
		}
	}
	logger.Info("retrieved instance metadata from IMDS", zap.String("resourceId", instanceData.Compute.ResourceID))

	nonce, err := c.getNonce(ctx, serviceClient, config, &v1.GetNonceRequest{
		ResourceId: instanceData.Compute.ResourceID,
	})
	if err != nil {
		logger.Error(err.Error())
		return nil, &bootstrapError{
			errorType: ErrorTypeGetNonceFailure,
			inner:     err,
		}
	}
	logger.Info("received new nonce from bootstrap server")

	attestedData, err := c.getAttestedData(ctx, nonce, config)
	if err != nil {
		logger.Error(err.Error())
		return nil, &bootstrapError{
			errorType: ErrorTypeGetAttestedDataFailure,
			inner:     err,
		}
	}
	logger.Info("retrieved instance attested data from IMDS")

	csrPEM, keyPEM, err := c.getCSR(ctx)
	if err != nil {
		logger.Error(err.Error())
		return nil, &bootstrapError{
			errorType: ErrorTypeGetCSRFailure,
			inner:     err,
		}
	}
	logger.Info("generated kubelet client CSR and associated private key")

	certPEM, err := c.getCredential(ctx, serviceClient, config, &v1.GetCredentialRequest{
		ResourceId:    instanceData.Compute.ResourceID,
		Nonce:         nonce,
		AttestedData:  attestedData.Signature,
		EncodedCsrPem: base64.StdEncoding.EncodeToString(csrPEM),
	})
	if err != nil {
		logger.Error(err.Error())
		return nil, &bootstrapError{
			errorType: ErrorTypeGetCredentialFailure,
			inner:     err,
		}
	}
	logger.Info("received valid kubelet client credential from bootstrap server")

	kubeconfigData, err := c.generateKubeconfig(ctx, certPEM, keyPEM, &kubeconfig.Config{
		APIServerFQDN:     config.APIServerFQDN,
		ClusterCAFilePath: config.ClusterCAFilePath,
		CertDir:           config.CertDir,
	})
	if err != nil {
		logger.Error(err.Error())
		return nil, &bootstrapError{
			errorType: ErrorTypeGenerateKubeconfigFailure,
			inner:     err,
		}
	}
	logger.Info("successfully generated new kubeconfig data")

	return kubeconfigData, nil
}

func (c *client) validateKubeConfig(ctx context.Context, config *Config) error {
	validateKubeconfigDeadline, cancel := context.WithTimeout(ctx, config.ValidateKubeconfigTimeout)
	defer cancel()
	endSpan := telemetry.StartSpan(ctx, "ValidateKubeconfig")
	defer endSpan()

	return c.kubeconfigValidator.Validate(validateKubeconfigDeadline, config.KubeconfigPath, config.EnsureAuthorizedClient)
}

func (c *client) getAccessToken(ctx context.Context, config *Config) (string, error) {
	getAccessTokenCtx, cancel := context.WithTimeout(ctx, config.GetAccessTokenTimeout)
	defer cancel()
	endSpan := telemetry.StartSpan(ctx, "GetAccessToken")
	defer endSpan()

	token, err := c.getToken(getAccessTokenCtx, config)
	if err != nil {
		return "", err
	}
	return token, nil
}

func (c *client) getServiceClient(ctx context.Context, token string, cfg *Config) (v1.SecureTLSBootstrapServiceClient, closeFunc, error) {
	endSpan := telemetry.StartSpan(ctx, "GetServiceClient")
	defer endSpan()

	serviceClient, closer, err := c.getServiceClientFunc(token, cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create bootstrap service client: %w", err)
	}

	return serviceClient, closer, nil
}

func (c *client) getInstanceData(ctx context.Context, config *Config) (*imds.VMInstanceData, error) {
	getInstanceDataCtx, cancel := context.WithTimeout(ctx, config.GetInstanceDataTimeout)
	defer cancel()
	endSpan := telemetry.StartSpan(ctx, "GetInstanceData")
	defer endSpan()

	instanceData, err := c.imdsClient.GetInstanceData(getInstanceDataCtx)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve instance metadata from IMDS: %w", err)
	}
	return instanceData, nil
}

func (c *client) getAttestedData(ctx context.Context, nonce string, config *Config) (*imds.VMAttestedData, error) {
	getAttestedDataCtx, cancel := context.WithTimeout(ctx, config.GetAttestedDataTimeout)
	defer cancel()
	endSpan := telemetry.StartSpan(ctx, "GetAttestedData")
	defer endSpan()

	attestedData, err := c.imdsClient.GetAttestedData(getAttestedDataCtx, nonce)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve instance attested data from IMDS: %w", err)
	}
	return attestedData, nil
}

func (c *client) getNonce(ctx context.Context, serviceClient v1.SecureTLSBootstrapServiceClient, config *Config, req *v1.GetNonceRequest) (string, error) {
	getNonceCtx, cancel := context.WithTimeout(ctx, config.GetNonceTimeout)
	defer cancel()
	endSpan := telemetry.StartSpan(ctx, "GetNonce")
	defer endSpan()

	nonceResponse, err := serviceClient.GetNonce(getNonceCtx, req)
	if err != nil {
		err = withLastGRPCRetryErrorIfDeadlineExceeded(err)
		return "", fmt.Errorf("failed to retrieve a nonce from bootstrap server: %w", err)
	}
	return nonceResponse.GetNonce(), nil
}

func (c *client) getCSR(ctx context.Context) ([]byte, []byte, error) {
	endSpan := telemetry.StartSpan(ctx, "GetCSR")
	defer endSpan()

	csrPEM, keyPEM, err := makeKubeletClientCSR(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create kubelet client CSR: %w", err)
	}
	return csrPEM, keyPEM, nil
}

func (c *client) getCredential(ctx context.Context, serviceClient v1.SecureTLSBootstrapServiceClient, config *Config, req *v1.GetCredentialRequest) ([]byte, error) {
	getCredentialCtx, cancel := context.WithTimeout(ctx, config.GetCredentialTimeout)
	defer cancel()
	endSpan := telemetry.StartSpan(ctx, "GetCredential")
	defer endSpan()

	credentialResponse, err := serviceClient.GetCredential(getCredentialCtx, req)
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

func (c *client) generateKubeconfig(ctx context.Context, certPEM, keyPEM []byte, config *kubeconfig.Config) (*clientcmdapi.Config, error) {
	endSpan := telemetry.StartSpan(ctx, "GenerateKubeconfig")
	defer endSpan()

	kubeconfigData, err := kubeconfig.GenerateForCertAndKey(certPEM, keyPEM, config)
	if err != nil {
		return nil, fmt.Errorf("failed to generate kubeconfig for new client cert and key: %w", err)
	}
	return kubeconfigData, nil
}
