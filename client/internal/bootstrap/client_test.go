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
	"github.com/Azure/aks-secure-tls-bootstrap/client/internal/log"
	"github.com/Azure/aks-secure-tls-bootstrap/client/internal/telemetry"
	"github.com/Azure/aks-secure-tls-bootstrap/client/internal/testutil"
	v1 "github.com/Azure/aks-secure-tls-bootstrap/service/pkg/gen/akssecuretlsbootstrap/v1"
	v1mocks "github.com/Azure/aks-secure-tls-bootstrap/service/pkg/gen/mock/akssecuretlsbootstrap/v1"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/fake"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
	"google.golang.org/grpc"
	"k8s.io/client-go/tools/clientcmd/api"
)

func TestBootstrapKubeletClientCredential(t *testing.T) {
	cases := []struct {
		name                     string
		setupMocks               func(config *Config, kubeconfigValidator *kubeconfigmocks.MockValidator, imdsClient *imdsmocks.MockClient, serviceClient *v1mocks.MockSecureTLSBootstrapServiceClient)
		// credentialFactory overrides newCredentialFromConfig. When nil, newCredentialFromConfig is used,
		// which exercises the real credential-creation path (including any error cases).
		credentialFactory        credentialFactoryFunc
		skipKubeconfigValidation bool
		expectedError            *bootstrapError
	}{
		{
			name: "kubeconfig is already valid",
			setupMocks: func(config *Config, kubeconfigValidator *kubeconfigmocks.MockValidator, imdsClient *imdsmocks.MockClient, serviceClient *v1mocks.MockSecureTLSBootstrapServiceClient) {
				config.KubeconfigPath = "path/to/kubeconfig"
				config.EnsureAuthorizedClient = true
				kubeconfigValidator.EXPECT().Validate(gomock.Any(), "path/to/kubeconfig", true).Return(nil).Times(1)
			},
			skipKubeconfigValidation: true,
			expectedError:            nil,
		},
		{
			name: "an access token cannot be retrieved",
			setupMocks: func(config *Config, kubeconfigValidator *kubeconfigmocks.MockValidator, imdsClient *imdsmocks.MockClient, serviceClient *v1mocks.MockSecureTLSBootstrapServiceClient) {
				config.CloudProviderConfig.ClientSecret = "" // force access token failure
				config.KubeconfigPath = "path/to/kubeconfig"
				config.EnsureAuthorizedClient = true
				kubeconfigValidator.EXPECT().Validate(gomock.Any(), "path/to/kubeconfig", true).Return(errors.New("kubeconfig is invalid")).Times(1)
			},
			// use real newCredentialFromConfig so that the empty client secret triggers a credential-creation error
			credentialFactory: newCredentialFromConfig,
			expectedError: &bootstrapError{
				errorType: ErrorTypeGetAccessTokenFailure,
				inner:     fmt.Errorf("generating service principal access token with client secret"),
			},
		},
		{
			name: "unable to retrieve instance data from IMDS",
			setupMocks: func(config *Config, kubeconfigValidator *kubeconfigmocks.MockValidator, imdsClient *imdsmocks.MockClient, serviceClient *v1mocks.MockSecureTLSBootstrapServiceClient) {
				config.KubeconfigPath = "path/to/kubeconfig"
				config.EnsureAuthorizedClient = true
				kubeconfigValidator.EXPECT().Validate(gomock.Any(), "path/to/kubeconfig", true).Return(errors.New("kubeconfig is invalid")).Times(1)
				imdsClient.EXPECT().GetInstanceData(gomock.Any()).Return(nil, errors.New("cannot get VM instance data from IMDS")).Times(1)
			},
			expectedError: &bootstrapError{
				errorType: ErrorTypeGetInstanceDataFailure,
				inner:     fmt.Errorf("failed to retrieve instance metadata"),
			},
		},
		{
			name: "unable to retrieve nonce from bootstrap server",
			setupMocks: func(config *Config, kubeconfigValidator *kubeconfigmocks.MockValidator, imdsClient *imdsmocks.MockClient, serviceClient *v1mocks.MockSecureTLSBootstrapServiceClient) {
				config.KubeconfigPath = "path/to/kubeconfig"
				config.EnsureAuthorizedClient = true
				kubeconfigValidator.EXPECT().Validate(gomock.Any(), "path/to/kubeconfig", true).Return(errors.New("kubeconfig is invalid")).Times(1)
				imdsClient.EXPECT().GetInstanceData(gomock.Any()).Return(&imds.VMInstanceData{Compute: imds.ComputeData{ResourceID: "rid"}}, nil).Times(1)
				serviceClient.EXPECT().GetNonce(gomock.Any(), &v1.GetNonceRequest{ResourceId: "rid"}).Return(&v1.GetNonceResponse{}, errors.New("cannot get nonce response")).Times(1)
			},
			expectedError: &bootstrapError{
				errorType: ErrorTypeGetNonceFailure,
				inner:     fmt.Errorf("failed to retrieve a nonce from bootstrap server"),
			},
		},
		{
			name: "unable to retrieve attested data from IMDS",
			setupMocks: func(config *Config, kubeconfigValidator *kubeconfigmocks.MockValidator, imdsClient *imdsmocks.MockClient, serviceClient *v1mocks.MockSecureTLSBootstrapServiceClient) {
				config.KubeconfigPath = "path/to/kubeconfig"
				config.EnsureAuthorizedClient = true
				kubeconfigValidator.EXPECT().Validate(gomock.Any(), "path/to/kubeconfig", true).Return(errors.New("kubeconfig is invalid")).Times(1)
				imdsClient.EXPECT().GetInstanceData(gomock.Any()).Return(&imds.VMInstanceData{Compute: imds.ComputeData{ResourceID: "rid"}}, nil).Times(1)
				serviceClient.EXPECT().GetNonce(gomock.Any(), &v1.GetNonceRequest{ResourceId: "rid"}).Return(&v1.GetNonceResponse{Nonce: "nonce"}, nil).Times(1)
				imdsClient.EXPECT().GetAttestedData(gomock.Any(), "nonce").Return(nil, errors.New("cannot get VM attested data")).Times(1)
			},
			expectedError: &bootstrapError{
				errorType: ErrorTypeGetAttestedDataFailure,
				inner:     fmt.Errorf("failed to retrieve instance attested data"),
			},
		},
		{
			name: "unable to retrieve a credential from the bootstrap server",
			setupMocks: func(config *Config, kubeconfigValidator *kubeconfigmocks.MockValidator, imdsClient *imdsmocks.MockClient, serviceClient *v1mocks.MockSecureTLSBootstrapServiceClient) {
				config.KubeconfigPath = "path/to/kubeconfig"
				config.EnsureAuthorizedClient = true
				kubeconfigValidator.EXPECT().Validate(gomock.Any(), "path/to/kubeconfig", true).Return(errors.New("kubeconfig is invalid")).Times(1)
				imdsClient.EXPECT().GetInstanceData(gomock.Any()).Return(&imds.VMInstanceData{Compute: imds.ComputeData{ResourceID: "rid"}}, nil).Times(1)
				serviceClient.EXPECT().GetNonce(gomock.Any(), &v1.GetNonceRequest{ResourceId: "rid"}).Return(&v1.GetNonceResponse{Nonce: "nonce"}, nil).Times(1)
				imdsClient.EXPECT().GetAttestedData(gomock.Any(), "nonce").Return(&imds.VMAttestedData{Signature: "signedBlob"}, nil).Times(1)
				serviceClient.EXPECT().GetCredential(gomock.Any(), gomock.Any()).DoAndReturn(func(ctx context.Context, req *v1.GetCredentialRequest, opts ...grpc.CallOption) (*v1.GetCredentialResponse, error) {
					assert.Equal(t, "rid", req.ResourceId)
					assert.Equal(t, "nonce", req.Nonce)
					assert.Equal(t, "signedBlob", req.AttestedData)
					assert.NotEmpty(t, req.EncodedCsrPem)
					return nil, errors.New("cannot get credential")
				}).Times(1)
			},
			expectedError: &bootstrapError{
				errorType: ErrorTypeGetCredentialFailure,
				inner:     fmt.Errorf("failed to retrieve new kubelet client credential from bootstrap server"),
			},
		},
		{
			name: "bootstrap server responds with an empty credential",
			setupMocks: func(config *Config, kubeconfigValidator *kubeconfigmocks.MockValidator, imdsClient *imdsmocks.MockClient, serviceClient *v1mocks.MockSecureTLSBootstrapServiceClient) {
				config.KubeconfigPath = "path/to/kubeconfig"
				config.EnsureAuthorizedClient = true
				kubeconfigValidator.EXPECT().Validate(gomock.Any(), "path/to/kubeconfig", true).Return(errors.New("kubeconfig is invalid")).Times(1)
				imdsClient.EXPECT().GetInstanceData(gomock.Any()).Return(&imds.VMInstanceData{Compute: imds.ComputeData{ResourceID: "rid"}}, nil).Times(1)
				serviceClient.EXPECT().GetNonce(gomock.Any(), &v1.GetNonceRequest{ResourceId: "rid"}).Return(&v1.GetNonceResponse{Nonce: "nonce"}, nil).Times(1)
				imdsClient.EXPECT().GetAttestedData(gomock.Any(), "nonce").Return(&imds.VMAttestedData{Signature: "signedBlob"}, nil).Times(1)
				serviceClient.EXPECT().GetCredential(gomock.Any(), gomock.Any()).DoAndReturn(func(ctx context.Context, req *v1.GetCredentialRequest, opts ...grpc.CallOption) (*v1.GetCredentialResponse, error) {
					assert.Equal(t, "rid", req.ResourceId)
					assert.Equal(t, "nonce", req.Nonce)
					assert.Equal(t, "signedBlob", req.AttestedData)
					assert.NotEmpty(t, req.EncodedCsrPem)
					return &v1.GetCredentialResponse{EncodedCertPem: ""}, nil
				}).Times(1)
			},
			expectedError: &bootstrapError{
				errorType: ErrorTypeGetCredentialFailure,
				inner:     fmt.Errorf("cert data from bootstrap server is empty"),
			},
		},
		{
			name: "bootstrap server responds with an invalid credential",
			setupMocks: func(config *Config, kubeconfigValidator *kubeconfigmocks.MockValidator, imdsClient *imdsmocks.MockClient, serviceClient *v1mocks.MockSecureTLSBootstrapServiceClient) {
				config.KubeconfigPath = "path/to/kubeconfig"
				config.EnsureAuthorizedClient = true
				kubeconfigValidator.EXPECT().Validate(gomock.Any(), "path/to/kubeconfig", true).Return(errors.New("kubeconfig is invalid")).Times(1)
				imdsClient.EXPECT().GetInstanceData(gomock.Any()).Return(&imds.VMInstanceData{Compute: imds.ComputeData{ResourceID: "rid"}}, nil).Times(1)
				serviceClient.EXPECT().GetNonce(gomock.Any(), &v1.GetNonceRequest{ResourceId: "rid"}).Return(&v1.GetNonceResponse{Nonce: "nonce"}, nil).Times(1)
				imdsClient.EXPECT().GetAttestedData(gomock.Any(), "nonce").Return(&imds.VMAttestedData{Signature: "signedBlob"}, nil).Times(1)
				serviceClient.EXPECT().GetCredential(gomock.Any(), gomock.Any()).DoAndReturn(func(ctx context.Context, req *v1.GetCredentialRequest, opts ...grpc.CallOption) (*v1.GetCredentialResponse, error) {
					assert.Equal(t, "rid", req.ResourceId)
					assert.Equal(t, "nonce", req.Nonce)
					assert.Equal(t, "signedBlob", req.AttestedData)
					assert.NotEmpty(t, req.EncodedCsrPem)
					return &v1.GetCredentialResponse{
						EncodedCertPem: "YW55IGNhcm5hbCBwbGVhc3U======", // base64 encoded invalid PEM
					}, nil
				}).Times(1)
			},
			expectedError: &bootstrapError{
				errorType: ErrorTypeGetCredentialFailure,
				inner:     fmt.Errorf("failed to decode cert data from bootstrap server"),
			},
		},
		{
			name: "a new credential can be generated",
			setupMocks: func(config *Config, kubeconfigValidator *kubeconfigmocks.MockValidator, imdsClient *imdsmocks.MockClient, serviceClient *v1mocks.MockSecureTLSBootstrapServiceClient) {
				clientCertPEM, _, err := testutil.GenerateCertPEM(testutil.CertTemplate{
					CommonName:   "system:node:node",
					Organization: "system:nodes",
					Expiration:   time.Now().Add(time.Hour),
				})
				assert.NoError(t, err)

				config.KubeconfigPath = "path/to/kubeconfig"
				config.EnsureAuthorizedClient = true
				kubeconfigValidator.EXPECT().Validate(gomock.Any(), "path/to/kubeconfig", true).Return(errors.New("kubeconfig is invalid")).Times(1)
				imdsClient.EXPECT().GetInstanceData(gomock.Any()).Return(&imds.VMInstanceData{Compute: imds.ComputeData{ResourceID: "rid"}}, nil).Times(1)
				serviceClient.EXPECT().GetNonce(gomock.Any(), &v1.GetNonceRequest{ResourceId: "rid"}).Return(&v1.GetNonceResponse{Nonce: "nonce"}, nil).Times(1)
				imdsClient.EXPECT().GetAttestedData(gomock.Any(), "nonce").Return(&imds.VMAttestedData{Signature: "signedBlob"}, nil).Times(1)
				serviceClient.EXPECT().GetCredential(gomock.Any(), gomock.Any()).DoAndReturn(func(ctx context.Context, req *v1.GetCredentialRequest, opts ...grpc.CallOption) (*v1.GetCredentialResponse, error) {
					assert.Equal(t, "rid", req.ResourceId)
					assert.Equal(t, "nonce", req.Nonce)
					assert.Equal(t, "signedBlob", req.AttestedData)
					assert.NotEmpty(t, req.EncodedCsrPem)
					return &v1.GetCredentialResponse{
						EncodedCertPem: base64.StdEncoding.EncodeToString(clientCertPEM), // base64 encoded invalid PEM
					}, nil
				}).Times(1)
			},
			expectedError: nil,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			mockCtrl := gomock.NewController(t)
			defer mockCtrl.Finish()

			kubeconfigValidator := kubeconfigmocks.NewMockValidator(mockCtrl)
			imdsClient := imdsmocks.NewMockClient(mockCtrl)
			serviceClient := v1mocks.NewMockSecureTLSBootstrapServiceClient(mockCtrl)

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
			certDir := filepath.Join(tempDir, "kubelet", "pki")

			err = os.WriteFile(clusterCAFilePath, clusterCACertPEM, os.ModePerm)
			assert.NoError(t, err)

			config := &Config{
				NextProto:               "bootstrap",
				AADResource:             "resource",
				ClusterCAFilePath:       clusterCAFilePath,
				CertDir:                 certDir,
				APIServerFQDN:           "controlplane.azmk8s.io",
				KubeconfigPath:          "path/to/kubeconfig",
				CloudProviderConfigPath: filepath.Join(tempDir, "azure.json"),
				CloudProviderConfig: &cloud.ProviderConfig{
					CloudName:    azurePublicCloudName,
					ClientID:     "service-principal-id",
					ClientSecret: "service-principal-secret",
					TenantID:     "tenantId",
				},
				GetAccessTokenTimeout:  500 * time.Millisecond,
				GetInstanceDataTimeout: 0 * time.Millisecond,
				GetNonceTimeout:        0 * time.Millisecond,
				GetAttestedDataTimeout: 0 * time.Millisecond,
				GetCredentialTimeout:   0 * time.Millisecond,
			}
			c.setupMocks(config, kubeconfigValidator, imdsClient, serviceClient)

			credentialFactory := c.credentialFactory
			if credentialFactory == nil {
				credentialFactory = func(_ context.Context, _ *Config) (azcore.TokenCredential, error) {
					return &fake.TokenCredential{}, nil
				}
			}
			client := &client{
				kubeconfigValidator:  kubeconfigValidator,
				imdsClient:           imdsClient,
				credentialFactory:    credentialFactory,
				getServiceClientFunc: func(_ string, _ *Config) (v1.SecureTLSBootstrapServiceClient, closeFunc, error) {
					return serviceClient, func() error { return nil }, nil
				},
			}

			kubeconfigData, err := client.bootstrap(telemetry.WithTracing(log.NewTestContext()), config)
			if c.expectedError == nil {
				assert.NoError(t, err)
				if c.skipKubeconfigValidation {
					assert.Nil(t, kubeconfigData)
				} else {
					assert.NotNil(t, kubeconfigData)
					expectCorrectKubeconfigData(t, kubeconfigData, config)
				}
			} else {
				assert.Nil(t, kubeconfigData)
				assert.Error(t, err)
				var bootstrapErr *bootstrapError
				assert.Error(t, err)
				assert.True(t, errors.As(err, &bootstrapErr))
				assert.Equal(t, c.expectedError.errorType, bootstrapErr.errorType)
				assert.ErrorContains(t, bootstrapErr.Unwrap(), c.expectedError.inner.Error())
			}
		})
	}
}

func expectCorrectKubeconfigData(t *testing.T, data *api.Config, config *Config) {
	assert.NotNil(t, data)

	// validate default configurations
	defaultCluster := data.Clusters["default-cluster"]
	assert.NotNil(t, defaultCluster)
	assert.Equal(t, "https://controlplane.azmk8s.io:443", defaultCluster.Server)
	assert.Equal(t, config.ClusterCAFilePath, defaultCluster.CertificateAuthority)
	assert.Contains(t, data.AuthInfos, "default-auth")

	defaultAuth := data.AuthInfos["default-auth"]
	assert.NotNil(t, defaultAuth)
	assert.Equal(t, "kubelet-client-current.pem", filepath.Base(defaultAuth.ClientCertificate))
	assert.Equal(t, config.CertDir, filepath.Dir(defaultAuth.ClientCertificate))
	assert.Equal(t, config.CertDir, filepath.Dir(defaultAuth.ClientKey))
	assert.Contains(t, data.Contexts, "default-context")

	defaultContext := data.Contexts["default-context"]
	assert.NotNil(t, defaultContext)
	assert.Equal(t, "default-cluster", defaultContext.Cluster)
	assert.Equal(t, "default-auth", defaultContext.AuthInfo)

	assert.Equal(t, "default-context", data.CurrentContext)

	// validate cert file contents
	fi, err := os.Lstat(defaultAuth.ClientCertificate)
	assert.NoError(t, err)
	assert.True(t, fi.Mode()&os.ModeSymlink == os.ModeSymlink)

	certPath, err := os.ReadFile(defaultAuth.ClientCertificate)
	assert.NoError(t, err)

	certBlock, rest := pem.Decode(certPath)
	assert.NotNil(t, certBlock)
	assert.NotEmpty(t, rest)

	cert, err := x509.ParseCertificate(certBlock.Bytes)
	assert.NoError(t, err)
	assert.NotNil(t, cert)
	assert.Equal(t, "system:node:node", cert.Subject.CommonName)
	assert.Equal(t, []string{"system:nodes"}, cert.Subject.Organization)

	keyData, rest := pem.Decode(rest)
	assert.NotNil(t, keyData)
	assert.Empty(t, rest)

	key, err := x509.ParseECPrivateKey(keyData.Bytes)
	assert.NoError(t, err)
	assert.NotNil(t, key)
}
