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
	"github.com/Azure/aks-secure-tls-bootstrap/client/internal/telemetry"
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

func TestBootstrapKubeletClientCredential(t *testing.T) {
	tests := []struct {
		name       string
		setupMocks func(context.Context, *Config, *imdsmocks.MockClient,
			*kubeconfigmocks.MockValidator, *akssecuretlsbootstrapv1_mocks.MockSecureTLSBootstrapServiceClient, *[]byte)
		expectedError        *BootstrapError
		assertKubeconfigData func(*testing.T, *clientcmdapi.Config, *Config, []byte)
	}{
		{
			name: "when specified kubeconfig is already valid",
			setupMocks: func(ctx context.Context, bootstrapConfig *Config, imdsClient *imdsmocks.MockClient,
				kubeconfigValidator *kubeconfigmocks.MockValidator, serviceClient *akssecuretlsbootstrapv1_mocks.MockSecureTLSBootstrapServiceClient, _ *[]byte) {
				kubeconfigValidator.EXPECT().Validate(bootstrapConfig.KubeconfigPath, false).Return(nil).Times(1)
				serviceClient.EXPECT().GetCredential(gomock.Any(), gomock.Any()).Times(0)
				serviceClient.EXPECT().GetNonce(gomock.Any(), gomock.Any()).Times(0)
				imdsClient.EXPECT().GetAttestedData(gomock.Any(), gomock.Any()).Times(0)
				imdsClient.EXPECT().GetInstanceData(gomock.Any()).Times(0)
			},
			expectedError: nil,
			assertKubeconfigData: func(t *testing.T, data *clientcmdapi.Config, _ *Config, _ []byte) {
				assert.Nil(t, data)
			},
		},
		{
			name: "when an access token cannot be retrieved",
			setupMocks: func(ctx context.Context, bootstrapConfig *Config, imdsClient *imdsmocks.MockClient,
				kubeconfigValidator *kubeconfigmocks.MockValidator, serviceClient *akssecuretlsbootstrapv1_mocks.MockSecureTLSBootstrapServiceClient, _ *[]byte) {
				bootstrapConfig.ProviderConfig.ClientSecret = "" // force access token failure
				kubeconfigValidator.EXPECT().Validate(bootstrapConfig.KubeconfigPath, false).
					Return(fmt.Errorf("invalid kubeconfig")).Times(1)
			},
			expectedError: &BootstrapError{
				errorType: ErrorTypeGetAccessTokenFailure,
				inner:     fmt.Errorf("generating SPN access token with username and password"),
			},
			assertKubeconfigData: func(t *testing.T, data *clientcmdapi.Config, _ *Config, _ []byte) {
				assert.Nil(t, data)
			},
		},
		{
			name: "when unable to retrieve instance data from IMDS",
			setupMocks: func(ctx context.Context, bootstrapConfig *Config, imdsClient *imdsmocks.MockClient,
				kubeconfigValidator *kubeconfigmocks.MockValidator, serviceClient *akssecuretlsbootstrapv1_mocks.MockSecureTLSBootstrapServiceClient, _ *[]byte) {
				kubeconfigValidator.EXPECT().Validate(bootstrapConfig.KubeconfigPath, false).
					Return(fmt.Errorf("invalid kubeconfig")).Times(1)
				imdsClient.EXPECT().GetInstanceData(ctx).
					Return(nil, errors.New("cannot get VM instance data from IMDS")).Times(1)
			},
			expectedError: &BootstrapError{
				errorType: ErrorTypeGetInstanceDataFailure,
				inner:     fmt.Errorf("failed to retrieve instance metadata"),
			},
			assertKubeconfigData: func(t *testing.T, data *clientcmdapi.Config, _ *Config, _ []byte) {
				assert.Nil(t, data)
			},
		},
		{
			name: "when unable to retrieve nonce from bootstrap server",
			setupMocks: func(ctx context.Context, bootstrapConfig *Config, imdsClient *imdsmocks.MockClient,
				kubeconfigValidator *kubeconfigmocks.MockValidator, serviceClient *akssecuretlsbootstrapv1_mocks.MockSecureTLSBootstrapServiceClient, _ *[]byte) {
				kubeconfigValidator.EXPECT().Validate(bootstrapConfig.KubeconfigPath, false).
					Return(fmt.Errorf("invalid kubeconfig")).Times(1)
				imdsClient.EXPECT().GetInstanceData(ctx).
					Return(&imds.VMInstanceData{}, nil).Times(1)
				serviceClient.EXPECT().GetNonce(ctx, gomock.Any()).
					Return(&akssecuretlsbootstrapv1.GetNonceResponse{}, errors.New("cannot get nonce response")).Times(1)
			},
			expectedError: &BootstrapError{
				errorType: ErrorTypeGetNonceFailure,
				inner:     fmt.Errorf("failed to retrieve a nonce from bootstrap server"),
			},
			assertKubeconfigData: func(t *testing.T, data *clientcmdapi.Config, _ *Config, _ []byte) {
				assert.Nil(t, data)
			},
		},
		{
			name: "when unable to retrieve attested data from IMDS",
			setupMocks: func(ctx context.Context, bootstrapConfig *Config, imdsClient *imdsmocks.MockClient,
				kubeconfigValidator *kubeconfigmocks.MockValidator, serviceClient *akssecuretlsbootstrapv1_mocks.MockSecureTLSBootstrapServiceClient, _ *[]byte) {
				kubeconfigValidator.EXPECT().Validate(bootstrapConfig.KubeconfigPath, false).
					Return(fmt.Errorf("invalid kubeconfig")).Times(1)
				imdsClient.EXPECT().GetInstanceData(ctx).
					Return(&imds.VMInstanceData{}, nil).Times(1)
				serviceClient.EXPECT().GetNonce(ctx, gomock.Any()).
					Return(&akssecuretlsbootstrapv1.GetNonceResponse{Nonce: "nonce"}, nil).Times(1)
				imdsClient.EXPECT().GetAttestedData(ctx, "nonce").
					Return(nil, errors.New("cannot get VM attested data")).Times(1)
			},
			expectedError: &BootstrapError{
				errorType: ErrorTypeGetAttestedDataFailure,
				inner:     fmt.Errorf("failed to retrieve instance attested data"),
			},
			assertKubeconfigData: func(t *testing.T, data *clientcmdapi.Config, _ *Config, _ []byte) {
				assert.Nil(t, data)
			},
		},
		{
			name: "when unable to retrieve a credential from the bootstrap server",
			setupMocks: func(ctx context.Context, bootstrapConfig *Config, imdsClient *imdsmocks.MockClient,
				kubeconfigValidator *kubeconfigmocks.MockValidator, serviceClient *akssecuretlsbootstrapv1_mocks.MockSecureTLSBootstrapServiceClient, _ *[]byte) {
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
			},
			expectedError: &BootstrapError{
				errorType: ErrorTypeGetCredentialFailure,
				inner:     fmt.Errorf("failed to retrieve new kubelet client credential from bootstrap server"),
			},
			assertKubeconfigData: func(t *testing.T, data *clientcmdapi.Config, _ *Config, _ []byte) {
				assert.Nil(t, data)
			},
		},
		{
			name: "when bootstrap server responds with an empty credential",
			setupMocks: func(ctx context.Context, bootstrapConfig *Config, imdsClient *imdsmocks.MockClient,
				kubeconfigValidator *kubeconfigmocks.MockValidator, serviceClient *akssecuretlsbootstrapv1_mocks.MockSecureTLSBootstrapServiceClient, _ *[]byte) {
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
			},
			expectedError: &BootstrapError{
				errorType: ErrorTypeGetCredentialFailure,
				inner:     fmt.Errorf("cert data from bootstrap server is empty"),
			},
			assertKubeconfigData: func(t *testing.T, data *clientcmdapi.Config, _ *Config, _ []byte) {
				assert.Nil(t, data)
			},
		},
		{
			name: "when bootstrap server responds with an invalid credential",
			setupMocks: func(ctx context.Context, bootstrapConfig *Config, imdsClient *imdsmocks.MockClient,
				kubeconfigValidator *kubeconfigmocks.MockValidator, serviceClient *akssecuretlsbootstrapv1_mocks.MockSecureTLSBootstrapServiceClient, _ *[]byte) {
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
			},
			expectedError: &BootstrapError{
				errorType: ErrorTypeGetCredentialFailure,
				inner:     fmt.Errorf("failed to decode cert data from bootstrap server"),
			},
			assertKubeconfigData: func(t *testing.T, data *clientcmdapi.Config, _ *Config, _ []byte) {
				assert.Nil(t, data)
			},
		},
		{
			name: "bootstrap server can generate a credential",
			setupMocks: func(ctx context.Context, bootstrapConfig *Config, imdsClient *imdsmocks.MockClient,
				kubeconfigValidator *kubeconfigmocks.MockValidator, serviceClient *akssecuretlsbootstrapv1_mocks.MockSecureTLSBootstrapServiceClient, clientCertBytes *[]byte) {
				clientCertPEM, _, err := testutil.GenerateCertPEM(testutil.CertTemplate{
					CommonName:   "system:node:node",
					Organization: "system:nodes",
					Expiration:   time.Now().Add(time.Hour),
				})
				assert.NoError(t, err)
				clientCertBlock, _ := pem.Decode(clientCertPEM)
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
				*clientCertBytes = clientCertBlock.Bytes
			},
			expectedError: nil,
			assertKubeconfigData: func(t *testing.T, data *clientcmdapi.Config, config *Config, clientCertBytes []byte) {
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
				assert.Equal(t, clientCertBytes, certBlock.Bytes)
				keyData, rest := pem.Decode(rest)
				assert.Empty(t, rest)
				assert.NotNil(t, keyData)
				key, err := x509.ParseECPrivateKey(keyData.Bytes)
				assert.NoError(t, err)
				assert.NotNil(t, key)
			},
		},
	}

	logger, _ := zap.NewDevelopment()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockCtrl := gomock.NewController(t)
			defer mockCtrl.Finish()

			ctx := telemetry.NewContext()
			imdsClient := imdsmocks.NewMockClient(mockCtrl)
			kubeconfigValidator := kubeconfigmocks.NewMockValidator(mockCtrl)
			serviceClient := akssecuretlsbootstrapv1_mocks.NewMockSecureTLSBootstrapServiceClient(mockCtrl)

			client := &Client{
				logger:              logger,
				imdsClient:          imdsClient,
				kubeconfigValidator: kubeconfigValidator,
				getServiceClientFunc: func(_ string, _ *Config) (akssecuretlsbootstrapv1.SecureTLSBootstrapServiceClient, closeFunc, error) {
					return serviceClient, func() error { return nil }, nil
				},
				extractAccessTokenFunc: func(token *adal.ServicePrincipalToken) (string, error) {
					assert.NotNil(t, token)
					return "token", nil
				},
			}

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

			config := &Config{
				NextProto:         "bootstrap",
				AADResource:       "resource",
				ClusterCAFilePath: clusterCAFilePath,
				CredFilePath:      credFilePath,
				APIServerFQDN:     "controlplane.azmk8s.io",
				KubeconfigPath:    "path/to/kubeconfig",
				ProviderConfig: cloud.ProviderConfig{
					CloudName:    azure.PublicCloud.Name,
					ClientID:     "service-principal-id",
					ClientSecret: "service-principal-secret",
					TenantID:     "tenantId",
				},
			}

			var clientCertBytes []byte
			tt.setupMocks(ctx, config, imdsClient, kubeconfigValidator, serviceClient, &clientCertBytes)
			kubeconfigData, err := client.BootstrapKubeletClientCredential(ctx, config)
			if tt.expectedError == nil {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
				var bootstrapErr *BootstrapError
				assert.Error(t, err)
				assert.True(t, errors.As(err, &bootstrapErr))
				assert.Equal(t, tt.expectedError.Type(), bootstrapErr.Type())
				assert.ErrorContains(t, bootstrapErr.Unwrap(), tt.expectedError.inner.Error())
			}
			tt.assertKubeconfigData(t, kubeconfigData, config, clientCertBytes)
		})
	}
}
