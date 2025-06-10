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
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

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

func setupBootstrapClientTestDeps(t *testing.T, logger *zap.Logger, ctrl *gomock.Controller) (*Client, context.Context,
	*imdsmocks.MockClient, *kubeconfigmocks.MockValidator,
	*akssecuretlsbootstrapv1_mocks.MockSecureTLSBootstrapServiceClient) {

	t.Helper()
	ctx := context.Background()

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

	return client, ctx, imdsClient, kubeconfigValidator, serviceClient
}

func TestBootstrapKubeletClientCredential(t *testing.T) {
	logger, _ := zap.NewDevelopment()

	tests := []struct {
		name                   string
		setupMocks             func(*testing.T, *gomock.Controller) (*Client, context.Context, *Config, []byte)
		expectedError          string
		expectedErrorType      ErrorType
		expectedKubeconfigData func(*testing.T, *clientcmdapi.Config, *Config, []byte)
	}{
		{
			name: "when specified kubeconfig is already valid",
			setupMocks: func(t *testing.T, ctrl *gomock.Controller) (*Client, context.Context, *Config, []byte) {
				client, ctx, imdsClient, kubeconfigValidator, serviceClient := setupBootstrapClientTestDeps(t, logger, ctrl)
				bootstrapConfig := setupConfig(t)
				kubeconfigValidator.EXPECT().Validate(bootstrapConfig.KubeconfigPath, false).Return(nil).Times(1)
				serviceClient.EXPECT().GetCredential(gomock.Any(), gomock.Any()).Times(0)
				serviceClient.EXPECT().GetNonce(gomock.Any(), gomock.Any()).Times(0)
				imdsClient.EXPECT().GetAttestedData(gomock.Any(), gomock.Any()).Times(0)
				imdsClient.EXPECT().GetInstanceData(gomock.Any()).Times(0)
				return client, ctx, bootstrapConfig, nil
			},
			expectedError: "",
			expectedKubeconfigData: func(t *testing.T, data *clientcmdapi.Config, _ *Config, _ []byte) {
				assert.Nil(t, data)
			},
			expectedErrorType: "",
		},
		{
			name: "when an access token cannot be retrieved",
			setupMocks: func(t *testing.T, ctrl *gomock.Controller) (*Client, context.Context, *Config, []byte) {
				client, ctx, _, kubeconfigValidator, _ := setupBootstrapClientTestDeps(t, logger, ctrl)
				bootstrapConfig := setupConfig(t)
				bootstrapConfig.ProviderConfig.ClientSecret = "" // force access token failure
				kubeconfigValidator.EXPECT().Validate(bootstrapConfig.KubeconfigPath, false).
					Return(fmt.Errorf("invalid kubeconfig")).Times(1)
				return client, ctx, bootstrapConfig, nil
			},
			expectedError:     "failed to generate access token for gRPC connection",
			expectedErrorType: ErrorTypeGetAccessTokenFailure,
			expectedKubeconfigData: func(t *testing.T, data *clientcmdapi.Config, _ *Config, _ []byte) {
				assert.Nil(t, data)
			},
		},
		{
			name: "when unable to retrieve instance data from IMDS",
			setupMocks: func(t *testing.T, ctrl *gomock.Controller) (*Client, context.Context, *Config, []byte) {
				client, ctx, imdsClient, kubeconfigValidator, _ := setupBootstrapClientTestDeps(t, logger, ctrl)
				bootstrapConfig := setupConfig(t)
				kubeconfigValidator.EXPECT().Validate(bootstrapConfig.KubeconfigPath, false).
					Return(fmt.Errorf("invalid kubeconfig")).Times(1)
				imdsClient.EXPECT().GetInstanceData(ctx).
					Return(nil, errors.New("cannot get VM instance data from IMDS")).Times(1)
				return client, ctx, bootstrapConfig, nil
			},
			expectedError:     "failed to retrieve instance metadata",
			expectedErrorType: ErrorTypeGetIntanceDataFailure,
			expectedKubeconfigData: func(t *testing.T, data *clientcmdapi.Config, _ *Config, _ []byte) {
				assert.Nil(t, data)
			},
		},
		{
			name: "when unable to retrieve nonce from bootstrap server",
			setupMocks: func(t *testing.T, ctrl *gomock.Controller) (*Client, context.Context, *Config, []byte) {
				client, ctx, imdsClient, kubeconfigValidator, serviceClient := setupBootstrapClientTestDeps(t, logger, ctrl)
				bootstrapConfig := setupConfig(t)
				kubeconfigValidator.EXPECT().Validate(bootstrapConfig.KubeconfigPath, false).
					Return(fmt.Errorf("invalid kubeconfig")).Times(1)
				imdsClient.EXPECT().GetInstanceData(ctx).
					Return(&imds.VMInstanceData{}, nil).Times(1)
				serviceClient.EXPECT().GetNonce(ctx, gomock.Any()).
					Return(&akssecuretlsbootstrapv1.GetNonceResponse{}, errors.New("cannot get nonce response")).Times(1)
				return client, ctx, bootstrapConfig, nil
			},
			expectedError:     "failed to retrieve a nonce from bootstrap server",
			expectedErrorType: ErrorTypeGetNonceFailure,
			expectedKubeconfigData: func(t *testing.T, data *clientcmdapi.Config, _ *Config, _ []byte) {
				assert.Nil(t, data)
			},
		},
		{
			name: "when unable to retrieve attested data from IMDS",
			setupMocks: func(t *testing.T, ctrl *gomock.Controller) (*Client, context.Context, *Config, []byte) {
				client, ctx, imdsClient, kubeconfigValidator, serviceClient := setupBootstrapClientTestDeps(t, logger, ctrl)
				bootstrapConfig := setupConfig(t)
				kubeconfigValidator.EXPECT().Validate(bootstrapConfig.KubeconfigPath, false).
					Return(fmt.Errorf("invalid kubeconfig")).Times(1)
				imdsClient.EXPECT().GetInstanceData(ctx).
					Return(&imds.VMInstanceData{}, nil).Times(1)
				serviceClient.EXPECT().GetNonce(ctx, gomock.Any()).
					Return(&akssecuretlsbootstrapv1.GetNonceResponse{Nonce: "nonce"}, nil).Times(1)
				imdsClient.EXPECT().GetAttestedData(ctx, "nonce").
					Return(nil, errors.New("cannot get VM attested data")).Times(1)
				return client, ctx, bootstrapConfig, nil
			},
			expectedError:     "failed to retrieve attested data",
			expectedErrorType: ErrorTypeGetAttestedDataFailure,
			expectedKubeconfigData: func(t *testing.T, data *clientcmdapi.Config, _ *Config, _ []byte) {
				assert.Nil(t, data)
			},
		},
		{
			name: "when unable to retrieve a credential from the bootstrap server",
			setupMocks: func(t *testing.T, ctrl *gomock.Controller) (*Client, context.Context, *Config, []byte) {
				client, ctx, imdsClient, kubeconfigValidator, serviceClient := setupBootstrapClientTestDeps(t, logger, ctrl)
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
				return client, ctx, bootstrapConfig, nil
			},
			expectedError:     "failed to retrieve new kubelet client credential from bootstrap server",
			expectedErrorType: ErrorTypeGetCredentialFailure,
			expectedKubeconfigData: func(t *testing.T, data *clientcmdapi.Config, _ *Config, _ []byte) {
				assert.Nil(t, data)
			},
		},
		{
			name: "when bootstrap server responds with an empty credential",
			setupMocks: func(t *testing.T, ctrl *gomock.Controller) (*Client, context.Context, *Config, []byte) {
				client, ctx, imdsClient, kubeconfigValidator, serviceClient := setupBootstrapClientTestDeps(t, logger, ctrl)
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
					Return(&akssecuretlsbootstrapv1.GetCredentialResponse{EncodedCertPem: ""}, nil).Times(1)
				return client, ctx, bootstrapConfig, nil
			},
			expectedError:     "cert data from bootstrap server is empty",
			expectedErrorType: ErrorTypeGetCredentialFailure,
			expectedKubeconfigData: func(t *testing.T, data *clientcmdapi.Config, _ *Config, _ []byte) {
				assert.Nil(t, data)
			},
		},
		{
			name: "when bootstrap server responds with an invalid credential",
			setupMocks: func(t *testing.T, ctrl *gomock.Controller) (*Client, context.Context, *Config, []byte) {
				client, ctx, imdsClient, kubeconfigValidator, serviceClient := setupBootstrapClientTestDeps(t, logger, ctrl)
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
					Return(&akssecuretlsbootstrapv1.GetCredentialResponse{
						EncodedCertPem: "YW55IGNhcm5hbCBwbGVhc3U======", // base64 encoded invalid PEM
					}, nil).Times(1)
				return client, ctx, bootstrapConfig, nil
			},
			expectedError:     "failed to decode cert data from bootstrap server",
			expectedErrorType: ErrorTypeGetCredentialFailure,
			expectedKubeconfigData: func(t *testing.T, data *clientcmdapi.Config, _ *Config, _ []byte) {
				assert.Nil(t, data)
			},
		},
		{
			name: "bootstrap server can generate a credential",
			setupMocks: func(t *testing.T, ctrl *gomock.Controller) (*Client, context.Context, *Config, []byte) {
				client, ctx, imdsClient, kubeconfigValidator, serviceClient := setupBootstrapClientTestDeps(t, logger, ctrl)
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
					Return(fmt.Errorf("invalid kubeconfig")).Times(1)
				imdsClient.EXPECT().GetInstanceData(ctx).
					Return(&imds.VMInstanceData{}, nil).Times(1)
				serviceClient.EXPECT().GetNonce(ctx, gomock.Any()).
					Return(&akssecuretlsbootstrapv1.GetNonceResponse{Nonce: "nonce"}, nil).Times(1)
				imdsClient.EXPECT().GetAttestedData(ctx, "nonce").
					Return(&imds.VMAttestedData{Signature: "signedBlob"}, nil).Times(1)
				serviceClient.EXPECT().GetCredential(ctx, gomock.Any()).
					Return(&akssecuretlsbootstrapv1.GetCredentialResponse{
						EncodedCertPem: base64.StdEncoding.EncodeToString(clientCertPEM),
					}, nil).Times(1)
				return client, ctx, bootstrapConfig, clientCertBlock.Bytes
			},
			expectedError: "",
			expectedKubeconfigData: func(t *testing.T, data *clientcmdapi.Config, config *Config, certBlockBytes []byte) {
				assert.NotNil(t, data)
				assert.Contains(t, data.Clusters, "default-cluster")
				defaultCluster := data.Clusters["default-cluster"]
				assert.Equal(t, "https://controlplane.azmk8s.io:443", defaultCluster.Server)
				assert.Equal(t, config.ClusterCAFilePath, defaultCluster.CertificateAuthority)
				assert.Contains(t, data.AuthInfos, "default-auth")
				defaultAuth := data.AuthInfos["default-auth"]
				assert.Equal(t, config.CredFilePath, defaultAuth.ClientCertificate)
				assert.Equal(t, config.CredFilePath, defaultAuth.ClientKey)
				assert.Contains(t, data.Contexts, "default-context")
				defaultContext := data.Contexts["default-context"]
				assert.Equal(t, "default-cluster", defaultContext.Cluster)
				assert.Equal(t, "default-auth", defaultContext.AuthInfo)
				assert.Equal(t, "default-context", data.CurrentContext)
				credData, err := os.ReadFile(config.CredFilePath)
				assert.NoError(t, err)
				certBlock, rest := pem.Decode(credData)
				assert.NotEmpty(t, rest)
				assert.Equal(t, certBlock.Bytes, certBlockBytes)
				keyData, rest := pem.Decode(rest)
				assert.Empty(t, rest)
				assert.NotNil(t, keyData)
				key, err := x509.ParseECPrivateKey(keyData.Bytes)
				assert.NoError(t, err)
				assert.NotNil(t, key)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			client, ctx, config, certBlockBytes := tt.setupMocks(t, ctrl)
			kubeconfigData, err := client.BootstrapKubeletClientCredential(ctx, config)
			if tt.expectedError == "" {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError)
				if tt.expectedErrorType != "" {
					expectBootstrapErrorWithType(t, err, tt.expectedErrorType)
				}
			}
			if tt.expectedKubeconfigData != nil {
				tt.expectedKubeconfigData(t, kubeconfigData, config, certBlockBytes)
			}
		})
	}
}

func expectBootstrapErrorWithType(t *testing.T, err error, expectedType ErrorType) {
	t.Helper()

	var bootstrapErr *BootstrapError
	assert.Error(t, err)
	assert.True(t, errors.As(err, &bootstrapErr))
	assert.Equal(t, expectedType, bootstrapErr.errorType)
}
