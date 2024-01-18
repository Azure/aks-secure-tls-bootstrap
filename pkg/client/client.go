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
	"time"

	"github.com/Azure/aks-tls-bootstrap-client/pkg/datamodel"
	secureTLSBootstrapService "github.com/Azure/aks-tls-bootstrap-client/pkg/protos"
	"go.uber.org/zap"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	restclient "k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/transport"
	certutil "k8s.io/client-go/util/cert"
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
	kubeConfigPath string
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
		kubeConfigPath:       opts.KubeconfigPath,
	}
}

func (c *tlsBootstrapClientImpl) GetBootstrapToken(ctx context.Context) (string, error) {
	isValid, err := isKubeConfigStillValid(c.kubeConfigPath, c.logger)
	if err != nil {
		return "", err
	}
	if isValid {
		return "", nil
	}
	// if it is not valid, continue bootstrapping put the contents of the private key and signed certificate in the kubeconfig

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

	// load kube config with new exec credential

	execCredentialBytes, err := json.Marshal(execCredentialWithToken)
	if err != nil {
		return "", fmt.Errorf("failed to marshal execCredential")
	}

	return string(execCredentialBytes), nil
}

func isKubeConfigStillValid(kubeConfigPath string, logger *zap.Logger) (bool, error) {
	logger.Debug("checking if kubeconfig exists...")

	_, err := os.Stat(kubeConfigPath)
	if os.IsNotExist(err) {
		logger.Debug("kubeconfig does not exist. bootstrapping will continue")
		return false, nil
	}
	if err != nil {
		logger.Debug("error reading existing bootstrap kubeconfig. bootstrapping will not continue", zap.Error(err))
		return false, nil // not returning an error so bootstrap can continue
	}

	isValid, err := isClientConfigStillValid(kubeConfigPath)
	if err != nil {
		return false, fmt.Errorf("unable to load kubeconfig: %v", err)
	}
	if isValid {
		logger.Debug("kubeconfig is valid. bootstrapping will not continue")
		return true, nil
	}

	logger.Debug("kubeconfig is invalid. bootstrapping will continue")
	return false, nil
}

// copied from https://github.com/kubernetes/kubernetes/blob/e45f5b089f770b1c8a1583f2792176bfe450bb47/pkg/kubelet/certificate/bootstrap/bootstrap.go#L231
// isClientConfigStillValid checks the provided kubeconfig to see if it has a valid
// client certificate. It returns true if the kubeconfig is valid, or an error if bootstrapping
// should stop immediately.
func isClientConfigStillValid(kubeconfigPath string) (bool, error) {
	_, err := os.Stat(kubeconfigPath)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("error reading existing bootstrap kubeconfig %s: %v", kubeconfigPath, err)
	}
	bootstrapClientConfig, err := loadRESTClientConfig(kubeconfigPath)
	if err != nil {
		utilruntime.HandleError(fmt.Errorf("unable to read existing bootstrap client config from %s: %v", kubeconfigPath, err))
		return false, nil
	}
	transportConfig, err := bootstrapClientConfig.TransportConfig()
	if err != nil {
		utilruntime.HandleError(fmt.Errorf("unable to load transport configuration from existing bootstrap client config read from %s: %v", kubeconfigPath, err))
		return false, nil
	}
	// has side effect of populating transport config data fields
	if _, err := transport.TLSConfigFor(transportConfig); err != nil {
		utilruntime.HandleError(fmt.Errorf("unable to load TLS configuration from existing bootstrap client config read from %s: %v", kubeconfigPath, err))
		return false, nil
	}
	certs, err := certutil.ParseCertsPEM(transportConfig.TLS.CertData)
	if err != nil {
		utilruntime.HandleError(fmt.Errorf("unable to load TLS certificates from existing bootstrap client config read from %s: %v", kubeconfigPath, err))
		return false, nil
	}
	if len(certs) == 0 {
		utilruntime.HandleError(fmt.Errorf("unable to read TLS certificates from existing bootstrap client config read from %s: %v", kubeconfigPath, err))
		return false, nil
	}
	now := time.Now()
	for _, cert := range certs {
		if now.After(cert.NotAfter) {
			utilruntime.HandleError(fmt.Errorf("part of the existing bootstrap client certificate in %s is expired: %v", kubeconfigPath, cert.NotAfter))
			return false, nil
		}
	}
	return true, nil
}

// copied from https://github.com/kubernetes/kubernetes/blob/e45f5b089f770b1c8a1583f2792176bfe450bb47/pkg/kubelet/certificate/bootstrap/bootstrap.go#L212
func loadRESTClientConfig(kubeconfig string) (*restclient.Config, error) {
	// Load structured kubeconfig data from the given path.
	loader := &clientcmd.ClientConfigLoadingRules{ExplicitPath: kubeconfig}
	loadedConfig, err := loader.Load()
	if err != nil {
		return nil, err
	}
	// Flatten the loaded data to a particular restclient.Config based on the current context.
	return clientcmd.NewNonInteractiveClientConfig(
		*loadedConfig,
		loadedConfig.CurrentContext,
		&clientcmd.ConfigOverrides{},
		loader,
	).ClientConfig()
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
