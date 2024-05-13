// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package client

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"

	"github.com/Azure/aks-secure-tls-bootstrap/client/pkg/aad"
	"github.com/Azure/aks-secure-tls-bootstrap/client/pkg/datamodel"
	"github.com/Azure/aks-secure-tls-bootstrap/client/pkg/imds"
	"github.com/Azure/aks-secure-tls-bootstrap/client/pkg/kubeconfig"
	secureTLSBootstrapService "github.com/Azure/aks-secure-tls-bootstrap/service/protos"
	"go.uber.org/zap"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

type GetKubeletClientCredentialOpts struct {
	APIServerFQDN              string
	CustomClientID             string
	NextProto                  string
	AADResource                string
	ClusterCAFilePath          string
	KubeconfigPath             string
	CertFilePath               string
	KeyFilePath                string
	InsecureSkipTLSVerify      bool
	EnsureClientAuthentication bool
	AzureConfig                *datamodel.AzureConfig
}

func (o *GetKubeletClientCredentialOpts) ValidateAndSet(azureConfigPath string) error {
	if azureConfigPath == "" {
		return fmt.Errorf("azure config path must be specified")
	}
	if o.ClusterCAFilePath == "" {
		return fmt.Errorf("cluster CA file path must be specified")
	}
	if o.APIServerFQDN == "" {
		return fmt.Errorf("apiserver FQDN must be specified")
	}
	if o.NextProto == "" {
		return fmt.Errorf("next proto header value must be specified")
	}
	if o.AADResource == "" {
		return fmt.Errorf("AAD resource must be specified")
	}
	if o.KubeconfigPath == "" {
		return fmt.Errorf("kubeconfig path must be specified")
	}
	if o.CertFilePath == "" {
		return fmt.Errorf("cert file path must be specified")
	}
	if o.KeyFilePath == "" {
		return fmt.Errorf("key file path must be specified")
	}

	azureConfig := &datamodel.AzureConfig{}
	azureConfigData, err := os.ReadFile(azureConfigPath)
	if err != nil {
		return fmt.Errorf("reading azure config data from %s: %w", azureConfigPath, err)
	}
	if err = json.Unmarshal(azureConfigData, azureConfig); err != nil {
		return fmt.Errorf("unmarshaling azure config data: %w", err)
	}
	o.AzureConfig = azureConfig

	return nil
}

type SecureTLSBootstrapClient struct {
	logger               *zap.Logger
	serviceClientFactory serviceClientFactoryFunc
	imdsClient           imds.Client
	aadClient            aad.Client
	kubeconfigValidator  kubeconfig.Validator
}

func NewSecureTLSBootstrapClient(logger *zap.Logger) (*SecureTLSBootstrapClient, error) {
	return &SecureTLSBootstrapClient{
		logger:               logger,
		serviceClientFactory: secureTLSBootstrapServiceClientFactory,
		imdsClient:           imds.NewClient(logger),
		aadClient:            aad.NewClient(logger),
		kubeconfigValidator:  kubeconfig.NewValidator(),
	}, nil
}

func (c *SecureTLSBootstrapClient) GetKubeletClientCredential(ctx context.Context, opts *GetKubeletClientCredentialOpts) (*clientcmdapi.Config, error) {
	err := c.kubeconfigValidator.Validate(opts.KubeconfigPath, opts.EnsureClientAuthentication)
	if err == nil {
		c.logger.Info("existing kubeconfig is valid, exiting without bootstrapping")
		return nil, nil
	}
	c.logger.Info("failed to validate existing kubeconfig, will continue to bootstrap", zap.String("kubeconfig", opts.KubeconfigPath), zap.Error(err))

	authToken, err := c.getAuthToken(ctx, opts.CustomClientID, opts.AADResource, opts.AzureConfig)
	if err != nil {
		c.logger.Error("failed to generate JWT for GRPC connection", zap.Error(err))
		return nil, fmt.Errorf("failed to generate JWT for GRPC connection: %w", err)
	}
	c.logger.Info("generated JWT for auth")

	serviceClient, conn, err := c.serviceClientFactory(ctx, c.logger, &serviceClientFactoryConfig{
		fqdn:                  opts.APIServerFQDN,
		clusterCAFilePath:     opts.ClusterCAFilePath,
		insecureSkipTLSVerify: opts.InsecureSkipTLSVerify,
		nextProto:             opts.NextProto,
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
	kubeconfigData, err := kubeconfig.GenerateForCertAndKey(certPEM, privateKey, &kubeconfig.GenerationConfig{
		APIServerFQDN:     opts.APIServerFQDN,
		ClusterCAFilePath: opts.ClusterCAFilePath,
		CertFilePath:      opts.CertFilePath,
		KeyFilePath:       opts.KeyFilePath,
	})
	if err != nil {
		c.logger.Error("failed to generate kubeconfig for new client cert and key", zap.Error(err))
		return nil, fmt.Errorf("failed to generate kubeconfig for new client cert and key: %w", err)
	}
	c.logger.Info("successfully generated new kubeconfig data")

	return kubeconfigData, nil
}
