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
	"github.com/Azure/aks-secure-tls-bootstrap/client/pkg/events"
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
	EventsDir                  string
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
	logger              *zap.Logger
	eventsConfig        *events.Config
	serviceDialer       serviceDialerFunc
	imdsClient          imds.Client
	aadClient           aad.Client
	kubeconfigValidator kubeconfig.Validator
}

func NewSecureTLSBootstrapClient(logger *zap.Logger, eventsConfig *events.Config) (*SecureTLSBootstrapClient, error) {
	return &SecureTLSBootstrapClient{
		logger:              logger,
		serviceDialer:       secureTLSBootstrapServiceDialer,
		imdsClient:          imds.NewClient(logger),
		aadClient:           aad.NewClient(logger),
		kubeconfigValidator: kubeconfig.NewValidator(),
		eventsConfig:        eventsConfig,
	}, nil
}

func (c *SecureTLSBootstrapClient) GetKubeletClientCredential(ctx context.Context, opts *GetKubeletClientCredentialOpts) (*clientcmdapi.Config, error) {
	// validate kubeconfig
	validateKubeconfig := events.Event[any]{
		Action: func() (any, error) {
			return nil, c.kubeconfigValidator.Validate(opts.KubeconfigPath, opts.EnsureClientAuthentication)
		},
		Name: "ValidateKubeconfig",
	}
	_, err := validateKubeconfig.Perform(c.eventsConfig)
	if err == nil {
		c.logger.Info("existing kubeconfig is valid, exiting without bootstrapping")
		return nil, nil
	}
	c.logger.Error("failed to validate existing kubeconfig, will continue to bootstrap", zap.String("kubeconfig", opts.KubeconfigPath), zap.Error(err))

	// get JWT for auth
	getAuthToken := events.Event[string]{
		Action: func() (string, error) {
			return c.getAuthToken(ctx, opts.CustomClientID, opts.AADResource, opts.AzureConfig)
		},
		Name: "GetJWTForAuth",
	}
	authToken, err := getAuthToken.Perform(c.eventsConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to generate JWT for GRPC connection: %w", err)
	}
	c.logger.Info("generated JWT token for auth")

	// setup bootstrap service connection with JWT
	dialSercureTLSBootstrapServer := events.Event[*dialResult]{
		Action: func() (*dialResult, error) {
			return c.serviceDialer(ctx, c.logger, &dialerConfig{
				fqdn:                  opts.APIServerFQDN,
				clusterCAData:         opts.ClusterCAData,
				insecureSkipTLSVerify: opts.InsecureSkipTLSVerify,
				nextProto:             opts.NextProto,
				authToken:             authToken,
			})
		},
		Name: "DialSecureTLSBootstrapServer",
	}
	c.logger.Debug("creating GRPC connection and bootstrap service client...")
	dialResult, err := dialSercureTLSBootstrapServer.Perform(c.eventsConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to setup bootstrap service connection: %w", err)
	}
	serviceClient := dialResult.serviceClient
	conn := dialResult.grpcConn
	if conn != nil {
		defer conn.Close()
	}
	c.logger.Info("created GRPC connection and bootstrap service client")

	// get IMDS instance data
	getInstanceData := events.Event[*datamodel.VMSSInstanceData]{
		Action: func() (*datamodel.VMSSInstanceData, error) {
			return c.imdsClient.GetInstanceData(ctx)
		},
		Name: "GetInstanceData",
	}
	c.logger.Debug("retrieving IMDS instance data...")
	instanceData, err := getInstanceData.Perform(c.eventsConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve instance metadata from IMDS: %w", err)
	}
	c.logger.Info("retrieved IMDS instance data", zap.String("vmResourceId", instanceData.Compute.ResourceID))

	// get nonce from bootstrap server
	getNonce := events.Event[*secureTLSBootstrapService.NonceResponse]{
		Action: func() (*secureTLSBootstrapService.NonceResponse, error) {
			return serviceClient.GetNonce(ctx, &secureTLSBootstrapService.NonceRequest{
				ResourceID: instanceData.Compute.ResourceID,
			})
		},
		Name: "GetNonce",
	}
	c.logger.Debug("retrieving nonce from bootstrap server...")
	nonceResponse, err := getNonce.Perform(c.eventsConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve a nonce from bootstrap server: %w", err)
	}
	c.logger.Info("received new nonce from bootstrap server")
	nonce := nonceResponse.GetNonce()

	// get attested data from IMDS using nonce
	getAttestedData := events.Event[*datamodel.VMSSAttestedData]{
		Action: func() (*datamodel.VMSSAttestedData, error) {
			return c.imdsClient.GetAttestedData(ctx, nonce)
		},
		Name: "GetAttestedData",
	}
	c.logger.Debug("retrieving IMDS attested data...")
	attestedData, err := getAttestedData.Perform(c.eventsConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve attested data from IMDS: %w", err)
	}
	c.logger.Info("retrieved attested data from IMDS")

	// resolve hostname
	resolveHostname := events.Event[string]{
		Action: func() (string, error) {
			return os.Hostname()
		},
		Name: "ResolveHostname",
	}
	c.logger.Debug("resolving hostname...")
	hostname, err := resolveHostname.Perform(c.eventsConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve own hostname for kubelet CSR creation: %w", err)
	}
	c.logger.Info("resolved hostname", zap.String("hostname", hostname))

	// generate kubelet client CSR
	getCSRKeyBundle := events.Event[*csrKeyBundle]{
		Action: func() (*csrKeyBundle, error) {
			return makeKubeletClientCSR(hostname)
		},
		Name: "GenerateKubeletClientCSR",
	}
	c.logger.Debug("generating kubelet client CSR and associated private key...")
	bundle, err := getCSRKeyBundle.Perform(c.eventsConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create kubelet client CSR: %w", err)
	}
	c.logger.Info("generated kubelet client CSR and associated private key")

	// request kubelet client credential from bootstrap server
	getCredential := events.Event[*secureTLSBootstrapService.CredentialResponse]{
		Action: func() (*secureTLSBootstrapService.CredentialResponse, error) {
			return serviceClient.GetCredential(ctx, &secureTLSBootstrapService.CredentialRequest{
				ResourceID:    instanceData.Compute.ResourceID,
				Nonce:         nonce,
				AttestedData:  attestedData.Signature,
				EncodedCSRPEM: base64.StdEncoding.EncodeToString(bundle.csrPEM),
			})
		},
		Name: "GetCredential",
	}
	c.logger.Debug("requesting kubelet client credential from bootstrap server...")
	credentialResponse, err := getCredential.Perform(c.eventsConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve new kubelet client credential from bootstrap server: %w", err)
	}
	c.logger.Info("received kubelet client credential from bootstrap server")

	// generate kubeconfig using credential
	generateKubeconfig := events.Event[*clientcmdapi.Config]{
		Action: func() (*clientcmdapi.Config, error) {
			encodedCertPEM := credentialResponse.GetEncodedCertPEM()
			if encodedCertPEM == "" {
				return nil, fmt.Errorf("cert data from bootstrap server is empty")
			}
			certPEM, err := base64.StdEncoding.DecodeString(encodedCertPEM)
			if err != nil {
				return nil, fmt.Errorf("failed to decode cert data from bootstrap server")
			}
			return kubeconfig.GenerateForCertAndKey(certPEM, bundle.privateKey, &kubeconfig.GenerateOpts{
				APIServerFQDN: opts.APIServerFQDN,
				ClusterCAData: opts.ClusterCAData,
			})
		},
		Name: "GenerateKubeconfig",
	}
	c.logger.Debug("decoding certificate data and generating kubeconfig data...")
	kubeconfigData, err := generateKubeconfig.Perform(c.eventsConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to generate kubeconfig for new client cert and key: %w", err)
	}
	c.logger.Info("successfully generated new kubeconfig data")

	return kubeconfigData, nil
}
