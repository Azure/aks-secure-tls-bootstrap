// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package bootstrap

import (
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
	"github.com/Azure/go-autorest/autorest/adal"
	"github.com/Azure/go-autorest/autorest/azure"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

func TestBootstrapKubeletClientCredential(t *testing.T) {
	cases := []struct {
		name                     string
		setupMocks               func(cfg *Config, imdsClient *imdsmocks.MockClient, kubeconfigValidator *kubeconfigmocks.MockValidator, serviceClient *v1mocks.MockSecureTLSBootstrapServiceClient)
		skipKubeconfigValidation bool
		expectedError            *BootstrapError
	}{
		{
			name: "specified kubeconfig is already valid",
			setupMocks: func(cfg *Config, imdsClient *imdsmocks.MockClient, kubeconfigValidator *kubeconfigmocks.MockValidator, serviceClient *v1mocks.MockSecureTLSBootstrapServiceClient) {
				kubeconfigValidator.EXPECT().Validate(gomock.Any(), cfg.KubeconfigPath, false).Return(nil).Times(1)
				serviceClient.EXPECT().GetCredential(gomock.Any(), gomock.Any()).Times(0)
				serviceClient.EXPECT().GetNonce(gomock.Any(), gomock.Any()).Times(0)
				imdsClient.EXPECT().GetAttestedData(gomock.Any(), gomock.Any()).Times(0)
				imdsClient.EXPECT().GetInstanceData(gomock.Any()).Times(0)
			},
			skipKubeconfigValidation: true,
			expectedError:            nil,
		},
		{
			name: "an access token cannot be retrieved",
			setupMocks: func(cfg *Config, imdsClient *imdsmocks.MockClient, kubeconfigValidator *kubeconfigmocks.MockValidator, serviceClient *v1mocks.MockSecureTLSBootstrapServiceClient) {
				cfg.ProviderConfig.ClientSecret = "" // force access token failure
				kubeconfigValidator.EXPECT().Validate(gomock.Any(), cfg.KubeconfigPath, false).
					Return(fmt.Errorf("invalid kubeconfig")).Times(1)
			},
			expectedError: &BootstrapError{
				errorType: ErrorTypeGetAccessTokenFailure,
				inner:     fmt.Errorf("generating SPN access token with username and password"),
			},
		},
		{
			name: "unable to retrieve instance data from IMDS",
			setupMocks: func(cfg *Config, imdsClient *imdsmocks.MockClient, kubeconfigValidator *kubeconfigmocks.MockValidator, serviceClient *v1mocks.MockSecureTLSBootstrapServiceClient) {
				kubeconfigValidator.EXPECT().Validate(gomock.Any(), cfg.KubeconfigPath, false).
					Return(fmt.Errorf("invalid kubeconfig")).Times(1)
				imdsClient.EXPECT().GetInstanceData(gomock.Any()).
					Return(nil, errors.New("cannot get VM instance data from IMDS")).Times(1)
			},
			expectedError: &BootstrapError{
				errorType: ErrorTypeGetInstanceDataFailure,
				inner:     fmt.Errorf("failed to retrieve instance metadata"),
			},
		},
		{
			name: "unable to retrieve nonce from bootstrap server",
			setupMocks: func(cfg *Config, imdsClient *imdsmocks.MockClient, kubeconfigValidator *kubeconfigmocks.MockValidator, serviceClient *v1mocks.MockSecureTLSBootstrapServiceClient) {
				kubeconfigValidator.EXPECT().Validate(gomock.Any(), cfg.KubeconfigPath, false).
					Return(fmt.Errorf("invalid kubeconfig")).Times(1)
				imdsClient.EXPECT().GetInstanceData(gomock.Any()).
					Return(&imds.VMInstanceData{}, nil).Times(1)
				serviceClient.EXPECT().GetNonce(gomock.Any(), gomock.Any()).
					Return(&v1.GetNonceResponse{}, errors.New("cannot get nonce response")).Times(1)
			},
			expectedError: &BootstrapError{
				errorType: ErrorTypeGetNonceFailure,
				inner:     fmt.Errorf("failed to retrieve a nonce from bootstrap server"),
			},
		},
		{
			name: "unable to retrieve attested data from IMDS",
			setupMocks: func(cfg *Config, imdsClient *imdsmocks.MockClient, kubeconfigValidator *kubeconfigmocks.MockValidator, serviceClient *v1mocks.MockSecureTLSBootstrapServiceClient) {
				kubeconfigValidator.EXPECT().Validate(gomock.Any(), cfg.KubeconfigPath, false).
					Return(fmt.Errorf("invalid kubeconfig")).Times(1)
				imdsClient.EXPECT().GetInstanceData(gomock.Any()).
					Return(&imds.VMInstanceData{}, nil).Times(1)
				serviceClient.EXPECT().GetNonce(gomock.Any(), gomock.Any()).
					Return(&v1.GetNonceResponse{Nonce: "nonce"}, nil).Times(1)
				imdsClient.EXPECT().GetAttestedData(gomock.Any(), "nonce").
					Return(nil, errors.New("cannot get VM attested data")).Times(1)
			},
			expectedError: &BootstrapError{
				errorType: ErrorTypeGetAttestedDataFailure,
				inner:     fmt.Errorf("failed to retrieve instance attested data"),
			},
		},
		{
			name: "unable to retrieve a credential from the bootstrap server",
			setupMocks: func(cfg *Config, imdsClient *imdsmocks.MockClient, kubeconfigValidator *kubeconfigmocks.MockValidator, serviceClient *v1mocks.MockSecureTLSBootstrapServiceClient) {
				kubeconfigValidator.EXPECT().Validate(gomock.Any(), cfg.KubeconfigPath, false).
					Return(fmt.Errorf("invalid kubeconfig")).Times(1)
				imdsClient.EXPECT().GetInstanceData(gomock.Any()).
					Return(&imds.VMInstanceData{}, nil).Times(1)
				serviceClient.EXPECT().GetNonce(gomock.Any(), gomock.Any()).
					Return(&v1.GetNonceResponse{Nonce: "nonce"}, nil).Times(1)
				imdsClient.EXPECT().GetAttestedData(gomock.Any(), "nonce").
					Return(&imds.VMAttestedData{Signature: "signedBlob"}, nil).Times(1)
				serviceClient.EXPECT().GetCredential(gomock.Any(), gomock.Any()).
					Return(nil, errors.New("cannot get credential")).Times(1)
			},
			expectedError: &BootstrapError{
				errorType: ErrorTypeGetCredentialFailure,
				inner:     fmt.Errorf("failed to retrieve new kubelet client credential from bootstrap server"),
			},
		},
		{
			name: "bootstrap server responds with an empty credential",
			setupMocks: func(cfg *Config, imdsClient *imdsmocks.MockClient, kubeconfigValidator *kubeconfigmocks.MockValidator, serviceClient *v1mocks.MockSecureTLSBootstrapServiceClient) {
				kubeconfigValidator.EXPECT().Validate(gomock.Any(), cfg.KubeconfigPath, false).
					Return(fmt.Errorf("invalid kubeconfig")).Times(1)
				imdsClient.EXPECT().GetInstanceData(gomock.Any()).
					Return(&imds.VMInstanceData{}, nil).Times(1)
				serviceClient.EXPECT().GetNonce(gomock.Any(), gomock.Any()).
					Return(&v1.GetNonceResponse{Nonce: "nonce"}, nil).Times(1)
				imdsClient.EXPECT().GetAttestedData(gomock.Any(), "nonce").
					Return(&imds.VMAttestedData{Signature: "signedBlob"}, nil).Times(1)
				serviceClient.EXPECT().GetCredential(gomock.Any(), gomock.Any()).
					Return(&v1.GetCredentialResponse{EncodedCertPem: ""}, nil).Times(1)
			},
			expectedError: &BootstrapError{
				errorType: ErrorTypeGetCredentialFailure,
				inner:     fmt.Errorf("cert data from bootstrap server is empty"),
			},
		},
		{
			name: "bootstrap server responds with an invalid credential",
			setupMocks: func(cfg *Config, imdsClient *imdsmocks.MockClient, kubeconfigValidator *kubeconfigmocks.MockValidator, serviceClient *v1mocks.MockSecureTLSBootstrapServiceClient) {
				kubeconfigValidator.EXPECT().Validate(gomock.Any(), cfg.KubeconfigPath, false).
					Return(fmt.Errorf("invalid kubeconfig")).Times(1)
				imdsClient.EXPECT().GetInstanceData(gomock.Any()).
					Return(&imds.VMInstanceData{}, nil).Times(1)
				serviceClient.EXPECT().GetNonce(gomock.Any(), gomock.Any()).
					Return(&v1.GetNonceResponse{Nonce: "nonce"}, nil).Times(1)
				imdsClient.EXPECT().GetAttestedData(gomock.Any(), "nonce").
					Return(&imds.VMAttestedData{Signature: "signedBlob"}, nil).Times(1)
				serviceClient.EXPECT().GetCredential(gomock.Any(), gomock.Any()).
					Return(&v1.GetCredentialResponse{
						EncodedCertPem: "YW55IGNhcm5hbCBwbGVhc3U======", // base64 encoded invalid PEM
					}, nil).Times(1)
			},
			expectedError: &BootstrapError{
				errorType: ErrorTypeGetCredentialFailure,
				inner:     fmt.Errorf("failed to decode cert data from bootstrap server"),
			},
		},
		{
			name: "a new credential can be generated",
			setupMocks: func(cfg *Config, imdsClient *imdsmocks.MockClient, kubeconfigValidator *kubeconfigmocks.MockValidator, serviceClient *v1mocks.MockSecureTLSBootstrapServiceClient) {
				clientCertPEM, _, err := testutil.GenerateCertPEM(testutil.CertTemplate{
					CommonName:   "system:node:node",
					Organization: "system:nodes",
					Expiration:   time.Now().Add(time.Hour),
				})
				assert.NoError(t, err)
				kubeconfigValidator.EXPECT().Validate(gomock.Any(), cfg.KubeconfigPath, false).
					Return(fmt.Errorf("invalid kubeconfig")).Times(1)
				imdsClient.EXPECT().GetInstanceData(gomock.Any()).
					Return(&imds.VMInstanceData{}, nil).Times(1)
				serviceClient.EXPECT().GetNonce(gomock.Any(), gomock.Any()).
					Return(&v1.GetNonceResponse{Nonce: "nonce"}, nil).Times(1)
				imdsClient.EXPECT().GetAttestedData(gomock.Any(), "nonce").
					Return(&imds.VMAttestedData{Signature: "signedBlob"}, nil).Times(1)
				serviceClient.EXPECT().GetCredential(gomock.Any(), gomock.Any()).
					Return(&v1.GetCredentialResponse{
						EncodedCertPem: base64.StdEncoding.EncodeToString(clientCertPEM),
					}, nil).Times(1)
			},
			expectedError: nil,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			mockCtrl := gomock.NewController(t)
			defer mockCtrl.Finish()

			imdsClient := imdsmocks.NewMockClient(mockCtrl)
			kubeconfigValidator := kubeconfigmocks.NewMockValidator(mockCtrl)
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

			client := &Client{
				imdsClient:          imdsClient,
				kubeconfigValidator: kubeconfigValidator,
				getServiceClientFunc: func(_ string, _ *Config) (v1.SecureTLSBootstrapServiceClient, closeFunc, error) {
					return serviceClient, func() error { return nil }, nil
				},
				extractAccessTokenFunc: func(token *adal.ServicePrincipalToken) (string, error) {
					assert.NotNil(t, token)
					return "token", nil
				},
			}
			config := &Config{
				NextProto:         "bootstrap",
				AADResource:       "resource",
				ClusterCAFilePath: clusterCAFilePath,
				CertDir:           certDir,
				APIServerFQDN:     "controlplane.azmk8s.io",
				KubeconfigPath:    "path/to/kubeconfig",
				ProviderConfig: cloud.ProviderConfig{
					CloudName:    azure.PublicCloud.Name,
					ClientID:     "service-principal-id",
					ClientSecret: "service-principal-secret",
					TenantID:     "tenantId",
				},
			}
			c.setupMocks(config, imdsClient, kubeconfigValidator, serviceClient)

			kubeconfigData, err := client.Bootstrap(telemetry.WithTracing(log.NewTestContext()), config)
			if c.expectedError == nil {
				assert.NoError(t, err)
				if !c.skipKubeconfigValidation {
					expectCorrectKubeconfigData(t, kubeconfigData, config)
				}
			} else {
				assert.Nil(t, kubeconfigData)
				assert.Error(t, err)
				assert.Equal(t, c.expectedError.errorType, GetErrorType(err))
				assert.ErrorContains(t, err, c.expectedError.inner.Error())
			}
		})
	}
}

func expectCorrectKubeconfigData(t *testing.T, data *clientcmdapi.Config, cfg *Config) {
	assert.NotNil(t, data)

	// validate default configurations
	defaultCluster := data.Clusters["default-cluster"]
	assert.NotNil(t, defaultCluster)
	assert.Equal(t, "https://controlplane.azmk8s.io:443", defaultCluster.Server)
	assert.Equal(t, cfg.ClusterCAFilePath, defaultCluster.CertificateAuthority)
	assert.Contains(t, data.AuthInfos, "default-auth")

	defaultAuth := data.AuthInfos["default-auth"]
	assert.NotNil(t, defaultAuth)
	assert.Equal(t, cfg.CertDir, filepath.Dir(defaultAuth.ClientCertificate))
	assert.Equal(t, cfg.CertDir, filepath.Dir(defaultAuth.ClientKey))
	assert.Contains(t, data.Contexts, "default-context")

	defaultContext := data.Contexts["default-context"]
	assert.NotNil(t, defaultContext)
	assert.Equal(t, "default-cluster", defaultContext.Cluster)
	assert.Equal(t, "default-auth", defaultContext.AuthInfo)
	assert.Equal(t, "default-context", data.CurrentContext)

	// validate cert file contents
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
