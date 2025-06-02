// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package bootstrap

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Azure/aks-secure-tls-bootstrap/client/internal/cloud"
	"github.com/Azure/aks-secure-tls-bootstrap/client/internal/imds"
	imdsmocks "github.com/Azure/aks-secure-tls-bootstrap/client/internal/imds/mocks"
	kubeconfigmocks "github.com/Azure/aks-secure-tls-bootstrap/client/internal/kubeconfig/mocks"
	"github.com/Azure/aks-secure-tls-bootstrap/client/internal/testutil"
	akssecuretlsbootstrapv1 "github.com/Azure/aks-secure-tls-bootstrap/service/pkg/gen/akssecuretlsbootstrap/v1"
	akssecuretlsbootstrapv1_mocks "github.com/Azure/aks-secure-tls-bootstrap/service/pkg/gen/mocks/akssecuretlsbootstrap/v1"
	"github.com/Azure/go-autorest/autorest/adal"
	"github.com/Azure/go-autorest/autorest/azure"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
	"go.uber.org/zap"
)

// TODO: refactor towards vanilla go tests

func setupConfig(t *testing.T) *Config {
	t.Helper()

	const (
		apiServerFQDN  = "controlplane.azmk8s.io"
		kubeconfigPath = "path/to/kubeconfig"
	)

	clusterCACertPEM, _, err := testutil.GenerateCertPEM(
		testutil.CertTemplate{
			CommonName:   "hcp",
			Organization: "aks",
			IsCA:         true,
			Expiration:   time.Now().Add(time.Hour),
		},
	)
	assert.NoError(t, err)

	tempDir := t.TempDir()
	clusterCAFilePath := filepath.Join(tempDir, "ca.crt")
	credFilePath := filepath.Join(tempDir, "client.pem")

	err = os.WriteFile(clusterCAFilePath, clusterCACertPEM, os.ModePerm)
	assert.NoError(t, err)

	return &Config{
		NextProto:         "bootstrap",
		AADResource:       "resource",
		ClusterCAFilePath: clusterCAFilePath,
		CredFilePath:      credFilePath,
		APIServerFQDN:     apiServerFQDN,
		KubeconfigPath:    kubeconfigPath,
		ProviderConfig: cloud.ProviderConfig{
			CloudName:    azure.PublicCloud.Name,
			ClientID:     "service-principal-id",
			ClientSecret: "service-principal-secret",
			TenantID:     "tenantId",
		},
	}
}

func setupBootstrapClientTestDeps(t *testing.T, logger *zap.Logger) (*Client, context.Context,
	*gomock.Controller, *imdsmocks.MockClient, *kubeconfigmocks.MockValidator,
	*akssecuretlsbootstrapv1_mocks.MockSecureTLSBootstrapServiceClient) {

	t.Helper()
	ctx := context.Background()
	ctrl := gomock.NewController(t)

	imdsClient := imdsmocks.NewMockClient(ctrl)
	kubeconfigValidator := kubeconfigmocks.NewMockValidator(ctrl)
	serviceClient := akssecuretlsbootstrapv1_mocks.NewMockSecureTLSBootstrapServiceClient(ctrl)

	client := &Client{
		logger:              logger,
		imdsClient:          imdsClient,
		kubeconfigValidator: kubeconfigValidator,
		getServiceClientFunc: func(_ string, _ *Config) (akssecuretlsbootstrapv1.SecureTLSBootstrapServiceClient, func() error, error) {
			return serviceClient, func() error { return nil }, nil
		},
		extractAccessTokenFunc: func(token *adal.ServicePrincipalToken) (string, error) {
			assert.NotNil(t, token)
			return "token", nil
		},
	}

	return client, ctx, ctrl, imdsClient, kubeconfigValidator, serviceClient
}

func TestBootstrapKubeletClientCredential(t *testing.T) {
	logger, _ := zap.NewDevelopment()

	t.Run("when specified kubeconfig is already valid", func(t *testing.T) {
		client, ctx, ctrl, imdsClient, kubeconfigValidator, serviceClient := setupBootstrapClientTestDeps(t, logger)
		defer ctrl.Finish()

		bootstrapConfig := setupConfig(t)

		kubeconfigValidator.EXPECT().Validate(bootstrapConfig.KubeconfigPath, false).Return(nil).Times(1)
		serviceClient.EXPECT().GetCredential(gomock.Any(), gomock.Any()).Times(0)
		serviceClient.EXPECT().GetNonce(gomock.Any(), gomock.Any()).Times(0)
		imdsClient.EXPECT().GetAttestedData(gomock.Any(), gomock.Any()).Times(0)
		imdsClient.EXPECT().GetInstanceData(gomock.Any()).Times(0)

		kubeconfigData, err := client.BootstrapKubeletClientCredential(ctx, bootstrapConfig)
		assert.NoError(t, err)
		assert.Nil(t, kubeconfigData)
	})

	t.Run("when an access token cannot be retrieved", func(t *testing.T) {
		client, ctx, ctrl, _, kubeconfigValidator, _ := setupBootstrapClientTestDeps(t, logger)
		defer ctrl.Finish()

		bootstrapConfig := setupConfig(t)
		bootstrapConfig.ProviderConfig.ClientSecret = "" // force access token failure

		kubeconfigValidator.EXPECT().Validate(bootstrapConfig.KubeconfigPath, false).
			Return(fmt.Errorf("invalid kubeconfig")).Times(1)

		kubeconfigData, err := client.BootstrapKubeletClientCredential(ctx, bootstrapConfig)
		assert.Nil(t, kubeconfigData)
		assert.Error(t, err)
		expectBootstrapErrorWithType(t, err, ErrorTypeGetAccessTokenFailure)
		assert.Contains(t, err.Error(), "failed to generate access token for gRPC connection")
		assert.Contains(t, err.Error(), "generating SPN access token with username and password")
	})

	t.Run("when unable to retrieve instance data from IMDS", func(t *testing.T) {
		client, ctx, ctrl, imdsClient, kubeconfigValidator, _ := setupBootstrapClientTestDeps(t, logger)
		defer ctrl.Finish()

		bootstrapConfig := setupConfig(t)

		kubeconfigValidator.EXPECT().Validate(bootstrapConfig.KubeconfigPath, false).
			Return(fmt.Errorf("invalid kubeconfig")).Times(1)
		imdsClient.EXPECT().GetInstanceData(ctx).
			Return(nil, errors.New("cannot get VM instance data from IMDS")).Times(1)

		kubeconfigData, err := client.BootstrapKubeletClientCredential(ctx, bootstrapConfig)
		assert.Nil(t, kubeconfigData)
		assert.Error(t, err)
		expectBootstrapErrorWithType(t, err, ErrorTypeGetIntanceDataFailure)
		assert.Contains(t, err.Error(), "failed to retrieve instance metadata")
		assert.Contains(t, err.Error(), "cannot get VM instance data from IMDS")
	})

	t.Run("when unable to retrieve nonce from bootstrap server", func(t *testing.T) {
		client, ctx, ctrl, imdsClient, kubeconfigValidator, serviceClient := setupBootstrapClientTestDeps(t, logger)
		defer ctrl.Finish()

		bootstrapConfig := setupConfig(t)

		kubeconfigValidator.EXPECT().Validate(bootstrapConfig.KubeconfigPath, false).
			Return(fmt.Errorf("invalid kubeconfig")).Times(1)
		imdsClient.EXPECT().GetInstanceData(ctx).
			Return(&imds.VMInstanceData{}, nil).Times(1)
		serviceClient.EXPECT().GetNonce(ctx, gomock.Any()).
			Return(&akssecuretlsbootstrapv1.GetNonceResponse{}, errors.New("cannot get nonce response")).Times(1)

		kubeconfigData, err := client.BootstrapKubeletClientCredential(ctx, bootstrapConfig)
		assert.Nil(t, kubeconfigData)
		assert.Error(t, err)
		expectBootstrapErrorWithType(t, err, ErrorTypeGetNonceFailure)
		assert.Contains(t, err.Error(), "failed to retrieve a nonce from bootstrap server")
		assert.Contains(t, err.Error(), "cannot get nonce response")
	})

	t.Run("when unable to retrieve attested data from IMDS", func(t *testing.T) {
		client, ctx, ctrl, imdsClient, kubeconfigValidator, serviceClient := setupBootstrapClientTestDeps(t, logger)
		defer ctrl.Finish()

		bootstrapConfig := setupConfig(t)

		kubeconfigValidator.EXPECT().Validate(bootstrapConfig.KubeconfigPath, false).
			Return(fmt.Errorf("invalid kubeconfig")).Times(1)
		imdsClient.EXPECT().GetInstanceData(ctx).
			Return(&imds.VMInstanceData{}, nil).Times(1)
		serviceClient.EXPECT().GetNonce(ctx, gomock.Any()).
			Return(&akssecuretlsbootstrapv1.GetNonceResponse{Nonce: "nonce"}, nil).Times(1)
		imdsClient.EXPECT().GetAttestedData(ctx, "nonce").
			Return(nil, errors.New("cannot get VM attested data")).Times(1)

		kubeconfigData, err := client.BootstrapKubeletClientCredential(ctx, bootstrapConfig)
		assert.Nil(t, kubeconfigData)
		assert.Error(t, err)
		expectBootstrapErrorWithType(t, err, ErrorTypeGetAttestedDataFailure)
		assert.Contains(t, err.Error(), "failed to retrieve attested data")
		assert.Contains(t, err.Error(), "cannot get VM attested data")
	})

	t.Run("when unable to retrieve a credential from the bootstrap server", func(t *testing.T) {
		client, ctx, ctrl, imdsClient, kubeconfigValidator, serviceClient := setupBootstrapClientTestDeps(t, logger)
		defer ctrl.Finish()

		bootstrapConfig := setupConfig(t)

		kubeconfigValidator.EXPECT().Validate(bootstrapConfig.KubeconfigPath, false).
			Return(fmt.Errorf("invalid kubeconfig")).Times(1)
		imdsClient.EXPECT().GetInstanceData(ctx).
			Return(&imds.VMInstanceData{}, nil).Times(1)
		serviceClient.EXPECT().GetNonce(ctx, gomock.Any()).
			Return(&akssecuretlsbootstrapv1.GetNonceResponse{Nonce: "nonce"}, nil).Times(1)
		imdsClient.EXPECT().GetAttestedData(ctx, "nonce").
			Return(&imds.VMAttestedData{Signature: "signedBlob"}, nil).Times(1)
		serviceClient.EXPECT().GetCredential(ctx, gomock.Any()).
			Return(nil, errors.New("cannot get credential")).Times(1)

		kubeconfigData, err := client.BootstrapKubeletClientCredential(ctx, bootstrapConfig)
		assert.Nil(t, kubeconfigData)
		assert.Error(t, err)
		expectBootstrapErrorWithType(t, err, ErrorTypeGetCredentialFailure)
		assert.Contains(t, err.Error(), "failed to retrieve new kubelet client credential from bootstrap server")
		assert.Contains(t, err.Error(), "cannot get credential")
	})

	t.Run("when bootstrap server responds with an empty credential", func(t *testing.T) {
		client, ctx, ctrl, imdsClient, kubeconfigValidator, serviceClient := setupBootstrapClientTestDeps(t, logger)
		defer ctrl.Finish()

		bootstrapConfig := setupConfig(t)

		kubeconfigValidator.EXPECT().Validate(bootstrapConfig.KubeconfigPath, false).
			Return(fmt.Errorf("invalid kubeconfig")).
			Times(1)
		imdsClient.EXPECT().GetInstanceData(ctx).
			Return(&imds.VMInstanceData{}, nil).
			Times(1)
		serviceClient.EXPECT().GetNonce(ctx, gomock.Any()).
			Return(&akssecuretlsbootstrapv1.GetNonceResponse{
				Nonce: "nonce",
			}, nil).
			Times(1)
		imdsClient.EXPECT().GetAttestedData(ctx, "nonce").
			Return(&imds.VMAttestedData{
				Signature: "signedBlob",
			}, nil).
			Times(1)
		serviceClient.EXPECT().GetCredential(ctx, gomock.Any()).
			Return(&akssecuretlsbootstrapv1.GetCredentialResponse{
				EncodedCertPem: "",
			}, nil).
			Times(1)

		kubeconfigData, err := client.BootstrapKubeletClientCredential(ctx, bootstrapConfig)
		assert.Nil(t, kubeconfigData)
		assert.Error(t, err)
		expectBootstrapErrorWithType(t, err, ErrorTypeGetCredentialFailure)
		assert.Contains(t, err.Error(), "cert data from bootstrap server is empty")
	})

	t.Run("when bootstrap server responds with an invalid credential", func(t *testing.T) {
		client, ctx, ctrl, imdsClient, kubeconfigValidator, serviceClient := setupBootstrapClientTestDeps(t, logger)
		defer ctrl.Finish()

		bootstrapConfig := setupConfig(t)

		kubeconfigValidator.EXPECT().Validate(bootstrapConfig.KubeconfigPath, false).
			Return(fmt.Errorf("invalid kubeconfig")).
			Times(1)
		imdsClient.EXPECT().GetInstanceData(ctx).
			Return(&imds.VMInstanceData{}, nil).
			Times(1)
		serviceClient.EXPECT().GetNonce(ctx, gomock.Any()).
			Return(&akssecuretlsbootstrapv1.GetNonceResponse{
				Nonce: "nonce",
			}, nil).
			Times(1)
		imdsClient.EXPECT().GetAttestedData(ctx, "nonce").
			Return(&imds.VMAttestedData{
				Signature: "signedBlob",
			}, nil).
			Times(1)
		serviceClient.EXPECT().GetCredential(ctx, gomock.Any()).
			Return(&akssecuretlsbootstrapv1.GetCredentialResponse{
				EncodedCertPem: "YW55IGNhcm5hbCBwbGVhc3U======", // base64 encoded invalid PEM
			}, nil).
			Times(1)

		kubeconfigData, err := client.BootstrapKubeletClientCredential(ctx, bootstrapConfig)
		assert.Nil(t, kubeconfigData)
		assert.Error(t, err)
		expectBootstrapErrorWithType(t, err, ErrorTypeGetCredentialFailure)
		assert.Contains(t, err.Error(), "failed to decode cert data from bootstrap server")
	})

	t.Run("bootstrap server can generate a credential", func(t *testing.T) {
		client, ctx, ctrl, imdsClient, kubeconfigValidator, serviceClient := setupBootstrapClientTestDeps(t, logger)
		defer ctrl.Finish()

		bootstrapConfig := setupConfig(t)

		clientCertPEM, _, err := testutil.GenerateCertPEM(testutil.CertTemplate{
			CommonName:   "system:node:node",
			Organization: "system:nodes",
			Expiration:   time.Now().Add(time.Hour),
		})
		assert.NoError(t, err)
		
		clientCertBlock, rest := pem.Decode(clientCertPEM)
		assert.Empty(t, rest)

		kubeconfigValidator.EXPECT().Validate(bootstrapConfig.KubeconfigPath, false).
			Return(fmt.Errorf("invalid kubeconfig")).
			Times(1)
		imdsClient.EXPECT().GetInstanceData(ctx).
			Return(&imds.VMInstanceData{}, nil).
			Times(1)
		serviceClient.EXPECT().GetNonce(ctx, gomock.Any()).
			Return(&akssecuretlsbootstrapv1.GetNonceResponse{
				Nonce: "nonce",
			}, nil).
			Times(1)
		imdsClient.EXPECT().GetAttestedData(ctx, "nonce").
			Return(&imds.VMAttestedData{
				Signature: "signedBlob",
			}, nil).
			Times(1)
		serviceClient.EXPECT().GetCredential(ctx, gomock.Any()).
			Return(&akssecuretlsbootstrapv1.GetCredentialResponse{
				EncodedCertPem: base64.StdEncoding.EncodeToString(clientCertPEM),
			}, nil).
			Times(1)

		kubeconfigData, err := client.BootstrapKubeletClientCredential(ctx, bootstrapConfig)
		assert.NoError(t, err)
		assert.NotNil(t, kubeconfigData)

		assert.Contains(t, kubeconfigData.Clusters, "default-cluster")
		defaultCluster := kubeconfigData.Clusters["default-cluster"]
		assert.Equal(t, "https://controlplane.azmk8s.io:443", defaultCluster.Server)
		assert.Equal(t, bootstrapConfig.ClusterCAFilePath, defaultCluster.CertificateAuthority)

		assert.Contains(t, kubeconfigData.AuthInfos, "default-auth")
		defaultAuth := kubeconfigData.AuthInfos["default-auth"]
		assert.Equal(t, bootstrapConfig.CredFilePath, defaultAuth.ClientCertificate)
		assert.Equal(t, bootstrapConfig.CredFilePath, defaultAuth.ClientKey)

		assert.Contains(t, kubeconfigData.Contexts, "default-context")
		defaultContext := kubeconfigData.Contexts["default-context"]
		assert.Equal(t, "default-cluster", defaultContext.Cluster)
		assert.Equal(t, "default-auth", defaultContext.AuthInfo)
		
		assert.Equal(t, "default-context", kubeconfigData.CurrentContext)
		
		credData, err := os.ReadFile(bootstrapConfig.CredFilePath)
		assert.NoError(t, err)

		certBlock, rest := pem.Decode(credData)
		assert.NotEmpty(t, rest)
		assert.Equal(t, clientCertBlock.Bytes, certBlock.Bytes)

		keyData, rest := pem.Decode(rest)
		assert.Empty(t, rest)
		assert.NotNil(t, keyData)

		key, err := x509.ParseECPrivateKey(keyData.Bytes)
		assert.NoError(t, err)
		assert.NotNil(t, key)
	})
}

func expectBootstrapErrorWithType(t *testing.T, err error, expectedType ErrorType) {
	t.Helper()

	var bootstrapErr *BootstrapError
	assert.Error(t, err)
	assert.True(t, errors.As(err, &bootstrapErr))
	assert.Equal(t, expectedType, bootstrapErr.errorType)
}
