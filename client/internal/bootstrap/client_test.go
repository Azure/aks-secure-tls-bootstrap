// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package bootstrap

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
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
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"go.uber.org/mock/gomock"
	"go.uber.org/zap"
)

// TODO: refactor towards vanilla go tests

var _ = Describe("Client tests", Ordered, func() {
	const (
		apiServerFQDN  = "controlplane.azmk8s.io"
		kubeconfigPath = "path/to/kubeconfig"
	)
	var (
		ctx                 context.Context
		mockCtrl            *gomock.Controller
		imdsClient          *imdsmocks.MockClient
		kubeconfigValidator *kubeconfigmocks.MockValidator
		serviceClient       *akssecuretlsbootstrapv1_mocks.MockSecureTLSBootstrapServiceClient
		bootstrapClient     *Client
		bootstrapConfig     *Config
		logger              *zap.Logger

		clusterCAFilePath string
		certFilePath      string
		keyFilePath       string
	)

	BeforeAll(func() {
		logger, _ = zap.NewDevelopment()

		clusterCACertPEM, _, err := testutil.GenerateCertPEM(
			testutil.CertTemplate{
				CommonName:   "hcp",
				Organization: "aks",
				IsCA:         true,
				Expiration:   time.Now().Add(time.Hour),
			},
		)
		Expect(err).To(BeNil())

		tempDir := GinkgoT().TempDir()
		clusterCAFilePath = filepath.Join(tempDir, "ca.crt")
		certFilePath = filepath.Join(tempDir, "client.crt")
		keyFilePath = filepath.Join(tempDir, "client.key")

		err = os.WriteFile(clusterCAFilePath, clusterCACertPEM, os.ModePerm)
		Expect(err).To(BeNil())
	})

	BeforeEach(func() {
		bootstrapConfig = &Config{
			NextProto:         "bootstrap",
			AADResource:       "resource",
			ClusterCAFilePath: clusterCAFilePath,
			CertFilePath:      certFilePath,
			KeyFilePath:       keyFilePath,
			APIServerFQDN:     apiServerFQDN,
			KubeconfigPath:    kubeconfigPath,
			ProviderConfig: cloud.ProviderConfig{
				CloudName:    azure.PublicCloud.Name,
				ClientID:     "service-principal-id",
				ClientSecret: "service-principal-secret",
				TenantID:     "tenantId",
			},
		}
	})

	Context("NewClient", func() {
		It("should return a new bootstrap client", func() {
			c, err := NewClient(logger)
			Expect(err).To(BeNil())
			Expect(c).ToNot(BeNil())
			Expect(c.logger).ToNot(BeNil())
			Expect(c.getServiceClientFunc).ToNot(BeNil())
			Expect(c.imdsClient).ToNot(BeNil())
			Expect(c.kubeconfigValidator).ToNot(BeNil())
			Expect(c.extractAccessTokenFunc).ToNot(BeNil())
		})
	})

	Context("BootstrapKubeletClientCredential", func() {
		BeforeEach(func() {
			ctx = context.Background()
			mockCtrl = gomock.NewController(GinkgoT())
			imdsClient = imdsmocks.NewMockClient(mockCtrl)
			kubeconfigValidator = kubeconfigmocks.NewMockValidator(mockCtrl)
			serviceClient = akssecuretlsbootstrapv1_mocks.NewMockSecureTLSBootstrapServiceClient(mockCtrl)

			bootstrapClient = &Client{
				logger:              logger,
				imdsClient:          imdsClient,
				kubeconfigValidator: kubeconfigValidator,
				getServiceClientFunc: func(_ *zap.Logger, _ string, _ *Config) (akssecuretlsbootstrapv1.SecureTLSBootstrapServiceClient, func() error, error) {
					return serviceClient, func() error { return nil }, nil
				},
				extractAccessTokenFunc: func(token *adal.ServicePrincipalToken) (string, error) {
					Expect(token).ToNot(BeNil())
					return "token", nil
				},
			}
		})

		AfterEach(func() {
			mockCtrl.Finish()
		})

		When("specified kubeconfig is already valid", func() {
			It("should peform a no-op", func() {
				kubeconfigValidator.EXPECT().Validate(kubeconfigPath, false).
					Return(nil).
					Times(1)
				serviceClient.EXPECT().GetCredential(gomock.Any(), gomock.Any()).Times(0)
				serviceClient.EXPECT().GetNonce(gomock.Any(), gomock.Any()).Times(0)
				imdsClient.EXPECT().GetAttestedData(gomock.Any(), gomock.Any()).Times(0)
				imdsClient.EXPECT().GetInstanceData(gomock.Any()).Times(0)

				kubeconfigData, err := bootstrapClient.BootstrapKubeletClientCredential(ctx, bootstrapConfig)
				Expect(err).To(BeNil())
				Expect(kubeconfigData).To(BeNil())
			})
		})

		When("an access token cannot be retrieved", func() {
			It("return an error", func() {
				bootstrapConfig.ProviderConfig.ClientSecret = "" // force a failure to generate service principal access token
				kubeconfigValidator.EXPECT().Validate(kubeconfigPath, false).
					Return(fmt.Errorf("invalid kubeconfig")).
					Times(1)

				kubeconfigData, err := bootstrapClient.BootstrapKubeletClientCredential(ctx, bootstrapConfig)
				Expect(kubeconfigData).To(BeNil())
				Expect(err).ToNot(BeNil())
				expectBootstrapErrorWithType(err, ErrorTypeGetAccessTokenFailure)
				Expect(err.Error()).To(ContainSubstring("failed to generate access token for gRPC connection"))
				Expect(err.Error()).To(ContainSubstring("generating SPN access token with username and password"))
			})
		})

		When("unable to retrieve instance data from IMDS", func() {
			It("should return an error", func() {
				kubeconfigValidator.EXPECT().Validate(kubeconfigPath, false).
					Return(fmt.Errorf("invalid kubeconfig")).
					Times(1)
				imdsClient.EXPECT().GetInstanceData(ctx).
					Return(nil, errors.New("cannot get VM instance data from IMDS")).
					Times(1)

				kubeconfigData, err := bootstrapClient.BootstrapKubeletClientCredential(ctx, bootstrapConfig)
				Expect(kubeconfigData).To(BeNil())
				Expect(err).ToNot(BeNil())
				expectBootstrapErrorWithType(err, ErrorTypeGetIntanceDataFailure)
				Expect(err.Error()).To(ContainSubstring("failed to retrieve instance metadata"))
				Expect(err.Error()).To(ContainSubstring("cannot get VM instance data from IMDS"))
			})
		})

		When("unable to retrieve nonce from bootstrap server", func() {
			It("should return an error", func() {
				kubeconfigValidator.EXPECT().Validate(kubeconfigPath, false).
					Return(fmt.Errorf("invalid kubeconfig")).
					Times(1)
				imdsClient.EXPECT().GetInstanceData(ctx).
					Return(&imds.VMInstanceData{}, nil).
					Times(1)
				serviceClient.EXPECT().GetNonce(ctx, gomock.Any()).
					Return(&akssecuretlsbootstrapv1.GetNonceResponse{}, errors.New("cannot get nonce response")).
					Times(1)

				kubeconfigData, err := bootstrapClient.BootstrapKubeletClientCredential(ctx, bootstrapConfig)
				Expect(kubeconfigData).To(BeNil())
				Expect(err).ToNot(BeNil())
				expectBootstrapErrorWithType(err, ErrorTypeGetNonceFailure)
				Expect(err.Error()).To(ContainSubstring("failed to retrieve a nonce from bootstrap server"))
				Expect(err.Error()).To(ContainSubstring("cannot get nonce response"))
			})
		})

		When("unable to retrieve attested data from IMDS", func() {
			It("should return an error", func() {
				kubeconfigValidator.EXPECT().Validate(kubeconfigPath, false).
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
					Return(nil, errors.New("cannot get VM attested data")).
					Times(1)

				kubeconfigData, err := bootstrapClient.BootstrapKubeletClientCredential(ctx, bootstrapConfig)
				Expect(kubeconfigData).To(BeNil())
				Expect(err).ToNot(BeNil())
				expectBootstrapErrorWithType(err, ErrorTypeGetAttestedDataFailure)
				Expect(err.Error()).To(ContainSubstring("failed to retrieve attested data"))
				Expect(err.Error()).To(ContainSubstring("cannot get VM attested data"))
			})
		})

		When("unable to retrieve a credential from the bootstrap server", func() {
			It("should return an error", func() {
				kubeconfigValidator.EXPECT().Validate(kubeconfigPath, false).
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
					Return(nil, errors.New("cannot get credential")).
					Times(1)

				kubeconfigData, err := bootstrapClient.BootstrapKubeletClientCredential(ctx, bootstrapConfig)
				Expect(kubeconfigData).To(BeNil())
				Expect(err).ToNot(BeNil())
				expectBootstrapErrorWithType(err, ErrorTypeGetCredentialFailure)
				Expect(err.Error()).To(ContainSubstring("failed to retrieve new kubelet client credential from bootstrap server"))
				Expect(err.Error()).To(ContainSubstring("cannot get credential"))
			})
		})

		When("bootstrap server responds with an empty credential", func() {
			It("should return an error", func() {
				kubeconfigValidator.EXPECT().Validate(kubeconfigPath, false).
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

				kubeconfigData, err := bootstrapClient.BootstrapKubeletClientCredential(ctx, bootstrapConfig)
				Expect(kubeconfigData).To(BeNil())
				Expect(err).ToNot(BeNil())
				expectBootstrapErrorWithType(err, ErrorTypeGetCredentialFailure)
				Expect(err.Error()).To(ContainSubstring("cert data from bootstrap server is empty"))
			})
		})

		When("bootstrap server responds with an invalid credential", func() {
			It("should return an error", func() {
				kubeconfigValidator.EXPECT().Validate(kubeconfigPath, false).
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
						EncodedCertPem: "YW55IGNhcm5hbCBwbGVhc3U======",
					}, nil).
					Times(1)

				kubeconfigData, err := bootstrapClient.BootstrapKubeletClientCredential(ctx, bootstrapConfig)
				Expect(kubeconfigData).To(BeNil())
				Expect(err).ToNot(BeNil())
				expectBootstrapErrorWithType(err, ErrorTypeGetCredentialFailure)
				Expect(err.Error()).To(ContainSubstring("failed to decode cert data from bootstrap server"))
			})
		})

		When("bootstrap server can generate a credential", func() {
			It("should return a new kubeconfig object referencing the new credential", func() {
				clientCertPEM, _, err := testutil.GenerateCertPEM(testutil.CertTemplate{
					CommonName:   "system:node:node",
					Organization: "system:nodes",
					Expiration:   time.Now().Add(time.Hour),
				})
				Expect(err).To(BeNil())

				kubeconfigValidator.EXPECT().Validate(kubeconfigPath, false).
					Return(fmt.Errorf("invalid kubeconfig")).
					Times(1)
				imdsClient.EXPECT().GetInstanceData(ctx).
					Return(&imds.VMInstanceData{
						Compute: imds.ComputeData{
							ResourceID: "resourceId",
						},
					}, nil).
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

				kubeconfigData, err := bootstrapClient.BootstrapKubeletClientCredential(ctx, bootstrapConfig)
				Expect(err).To(BeNil())
				Expect(kubeconfigData).ToNot(BeNil())

				Expect(kubeconfigData.Clusters).To(HaveKey("default-cluster"))
				defaultCluster := kubeconfigData.Clusters["default-cluster"]
				Expect(defaultCluster.Server).To(Equal("https://controlplane.azmk8s.io:443"))
				Expect(defaultCluster.CertificateAuthority).To(Equal(bootstrapConfig.ClusterCAFilePath))

				Expect(kubeconfigData.AuthInfos).To(HaveKey("default-auth"))
				defaultAuth := kubeconfigData.AuthInfos["default-auth"]
				Expect(defaultAuth.ClientCertificate).To(Equal(bootstrapConfig.CertFilePath))
				Expect(defaultAuth.ClientKey).To(Equal(bootstrapConfig.KeyFilePath))

				Expect(kubeconfigData.Contexts).To(HaveKey("default-context"))
				defaultContext := kubeconfigData.Contexts["default-context"]
				Expect(defaultContext.Cluster).To(Equal("default-cluster"))
				Expect(defaultContext.AuthInfo).To(Equal("default-auth"))

				Expect(kubeconfigData.CurrentContext).To(Equal("default-context"))

				certData, err := os.ReadFile(bootstrapConfig.CertFilePath)
				Expect(err).To(BeNil())
				Expect(certData).To(Equal(clientCertPEM))

				keyData, err := os.ReadFile(bootstrapConfig.KeyFilePath)
				Expect(err).To(BeNil())
				Expect(keyData).ToNot(BeEmpty())
			})
		})
	})
})

func expectBootstrapErrorWithType(err error, expectedType ErrorType) {
	var bootstrapErr *BootstrapError
	Expect(errors.As(err, &bootstrapErr)).To(BeTrue())
	Expect(bootstrapErr.errorType).To(Equal(expectedType))
}
