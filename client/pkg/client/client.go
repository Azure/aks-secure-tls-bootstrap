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
	ClusterCAData              []byte
	APIServerFQDN              string
	CustomClientID             string
	NextProto                  string
	AADResource                string
	KubeconfigPath             string
	InsecureSkipTLSVerify      bool
	EnsureClientAuthentication bool
	AzureConfig                *datamodel.AzureConfig
}

func (o *GetKubeletClientCredentialOpts) ValidateAndSet(azureConfigPath, clusterCAFilePath string) error {
	if azureConfigPath == "" {
		return fmt.Errorf("azure config path must be specified")
	}
	if clusterCAFilePath == "" {
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
		return fmt.Errorf("kubeconfig must be specified")
	}
	azureConfig := &datamodel.AzureConfig{}
	azureConfigData, err := os.ReadFile(azureConfigPath)
	if err != nil {
		return fmt.Errorf("reading azure config data from %s: %w", azureConfigPath, err)
	}
	if err = json.Unmarshal(azureConfigData, azureConfig); err != nil {
		return fmt.Errorf("unmarshaling azure config data: %w", err)
	}
	clusterCAData, err := os.ReadFile(clusterCAFilePath)
	if err != nil {
		return fmt.Errorf("reading cluster CA data from %s: %w", clusterCAFilePath, err)
	}
	o.AzureConfig = azureConfig
	o.ClusterCAData = clusterCAData
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
	c.logger.Error("failed to validate existing kubeconfig, will continue to bootstrap", zap.String("kubeconfig", opts.KubeconfigPath), zap.Error(err))

	c.logger.Debug("generating JWT token for auth...")
	authToken, err := c.getAuthToken(ctx, opts.CustomClientID, opts.AADResource, opts.AzureConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to generate JWT token for GRPC connection: %w", err)
	}
	c.logger.Info("generated JWT token for auth")

	c.logger.Debug("creating GRPC connection and bootstrap service client...")
	serviceClient, conn, err := c.serviceClientFactory(ctx, c.logger, serviceClientFactoryOpts{
		fqdn:                  opts.APIServerFQDN,
		clusterCAData:         opts.ClusterCAData,
		insecureSkipTLSVerify: opts.InsecureSkipTLSVerify,
		nextProto:             opts.NextProto,
		authToken:             authToken,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to setup bootstrap service connection: %w", err)
	}
	if conn != nil {
		// conn should be non-nil if there's no error, though we need this to handle
		// cases created by unit tests
		defer conn.Close()
	}
	c.logger.Info("created GRPC connection and bootstrap service client")

	c.logger.Debug("retrieving IMDS instance data...")
	instanceData, err := c.imdsClient.GetInstanceData(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve instance metadata from IMDS: %w", err)
	}
	c.logger.Info("retrieved IMDS instance data", zap.String("vmResourceId", instanceData.Compute.ResourceID))

	c.logger.Debug("retrieving nonce from bootstrap server...")
	nonceResponse, err := serviceClient.GetNonce(ctx, &secureTLSBootstrapService.NonceRequest{
		ResourceID: instanceData.Compute.ResourceID,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve a nonce from bootstrap server: %w", err)
	}
	c.logger.Info("received new nonce from bootstrap server")
	nonce := nonceResponse.GetNonce()

	c.logger.Debug("retrieving IMDS attested data...")
	attestedData, err := c.imdsClient.GetAttestedData(ctx, nonce)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve attested data from IMDS: %w", err)
	}
	c.logger.Info("retrieved IMDS attested data")

	c.logger.Debug("resolving hostname...")
	hostname, err := os.Hostname()
	if err != nil {
		return nil, fmt.Errorf("failed to resolve own hostname for kubelet CSR creation: %w", err)
	}
	c.logger.Info("resolved hostname", zap.String("hostname", hostname))

	c.logger.Debug("generating kubelet client CSR and associated private key...")
	csrPEM, privateKey, err := makeKubeletClientCSR(hostname)
	if err != nil {
		return nil, fmt.Errorf("failed to create kubelet client CSR: %w", err)
	}
	c.logger.Info("generated kubelet client CSR and associated private key")

	c.logger.Debug("requesting kubelet client credential from bootstrap server...")
	credentialResponse, err := serviceClient.GetCredential(ctx, &secureTLSBootstrapService.CredentialRequest{
		ResourceID:    instanceData.Compute.ResourceID,
		Nonce:         nonce,
		AttestedData:  attestedData.Signature,
		EncodedCSRPEM: base64.StdEncoding.EncodeToString(csrPEM),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve new kubelet client credential from bootstrap server: %w", err)
	}
	c.logger.Info("received kubelet client credential from bootstrap server")

	c.logger.Debug("decoding certificate data and generating kubeconfig data...")
	encodedCertPEM := credentialResponse.GetEncodedCertPEM()
	if encodedCertPEM == "" {
		return nil, fmt.Errorf("cert data from bootstrap server is empty")
	}
	certPEM, err := base64.StdEncoding.DecodeString(encodedCertPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to decode cert data from bootstrap server")
	}
	kubeconfigData, err := kubeconfig.GenerateForCertAndKey(certPEM, privateKey, &kubeconfig.GenerateOpts{
		APIServerFQDN: opts.APIServerFQDN,
		ClusterCAData: opts.ClusterCAData,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to generate kubeconfig for new client cert and key: %w", err)
	}
	c.logger.Info("successfully generated new kubeconfig data")

	return kubeconfigData, nil
}
