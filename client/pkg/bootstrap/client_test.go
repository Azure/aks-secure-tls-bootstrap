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

	aadmocks "github.com/Azure/aks-secure-tls-bootstrap/client/pkg/aad/mocks"
	"github.com/Azure/aks-secure-tls-bootstrap/client/pkg/datamodel"
	imdsmocks "github.com/Azure/aks-secure-tls-bootstrap/client/pkg/imds/mocks"
	kubeconfigmocks "github.com/Azure/aks-secure-tls-bootstrap/client/pkg/kubeconfig/mocks"
	"github.com/Azure/aks-secure-tls-bootstrap/client/pkg/testutil"
	secureTLSBootstrapService "github.com/Azure/aks-secure-tls-bootstrap/service/protos"
	servicemocks "github.com/Azure/aks-secure-tls-bootstrap/service/protos/mocks"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"go.uber.org/mock/gomock"
	"go.uber.org/zap"
	"google.golang.org/grpc"
)

var _ = Describe("Client tests", Ordered, func() {
	const (
		apiServerFQDN  = "controlplane.azmk8s.io"
		kubeconfigPath = "path/to/kubeconfig"
	)
	var (
		ctx                 context.Context
		mockCtrl            *gomock.Controller
		imdsClient          *imdsmocks.MockClient
		aadClient           *aadmocks.MockClient
		kubeconfigValidator *kubeconfigmocks.MockValidator
		serviceClient       *servicemocks.MockSecureTLSBootstrapServiceClient
		bootstrapClient     *Client
		bootstrapConfig     *Config
		logger              *zap.Logger
	)

	BeforeAll(func() {
		logger, _ = zap.NewDevelopment()

		clusterCACertPEM, _, err := testutil.GenerateCertPEMWithExpiration(
			testutil.CertTemplate{
				CommonName:   "hcp",
				Organization: "aks",
				IsCA:         true,
				Expiration:   time.Now().Add(time.Hour),
			},
		)
		Expect(err).To(BeNil())

		tempDir := GinkgoT().TempDir()
		clusterCAFilePath := filepath.Join(tempDir, "ca.crt")
		err = os.WriteFile(clusterCAFilePath, clusterCACertPEM, os.ModePerm)
		Expect(err).To(BeNil())

		clientCertPath := filepath.Join(tempDir, "client.crt")
		clientKeyPath := filepath.Join(tempDir, "client.key")

		bootstrapConfig = &Config{
			NextProto:         "bootstrap",
			ClusterCAFilePath: clusterCAFilePath,
			CertFilePath:      clientCertPath,
			KeyFilePath:       clientKeyPath,
			APIServerFQDN:     apiServerFQDN,
			KubeconfigPath:    kubeconfigPath,
			AzureConfig: &datamodel.AzureConfig{
				ClientID:     "clientId",
				ClientSecret: "clientSecret",
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
			Expect(c.serviceClientFactory).ToNot(BeNil())
			Expect(c.aadClient).ToNot(BeNil())
			Expect(c.imdsClient).ToNot(BeNil())
			Expect(c.kubeconfigValidator).ToNot(BeNil())
		})
	})

	Context("GetKubeletClientCredential", func() {
		BeforeEach(func() {
			ctx = context.Background()
			mockCtrl = gomock.NewController(GinkgoT())
			imdsClient = imdsmocks.NewMockClient(mockCtrl)
			aadClient = aadmocks.NewMockClient(mockCtrl)
			kubeconfigValidator = kubeconfigmocks.NewMockValidator(mockCtrl)
			serviceClient = servicemocks.NewMockSecureTLSBootstrapServiceClient(mockCtrl)

			bootstrapClient = &Client{
				logger:              logger,
				imdsClient:          imdsClient,
				aadClient:           aadClient,
				kubeconfigValidator: kubeconfigValidator,
			}
			bootstrapClient.serviceClientFactory = func(
				ctx context.Context,
				logger *zap.Logger,
				cfg *serviceClientFactoryConfig) (secureTLSBootstrapService.SecureTLSBootstrapServiceClient, *grpc.ClientConn, error) {
				return serviceClient, nil, nil
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
				imdsClient.EXPECT().GetMSIToken(gomock.Any(), gomock.Any(), gomock.Any()).Times(0)
				aadClient.EXPECT().GetToken(gomock.Any(), gomock.Any(), gomock.Any()).Times(0)

				kubeconfigData, err := bootstrapClient.GetKubeletClientCredential(ctx, bootstrapConfig)
				Expect(err).To(BeNil())
				Expect(kubeconfigData).To(BeNil())
			})
		})

		When("an auth token cannot be retrieved", func() {
			It("return an error", func() {
				kubeconfigValidator.EXPECT().Validate(kubeconfigPath, false).
					Return(fmt.Errorf("invalid kubeconfig")).
					Times(1)
				aadClient.EXPECT().GetToken(ctx, gomock.Any(), bootstrapConfig.AADResource).
					Return("", fmt.Errorf("cannot retrieve AAD token")).
					Times(1)

				kubeconfigData, err := bootstrapClient.GetKubeletClientCredential(ctx, bootstrapConfig)
				Expect(kubeconfigData).To(BeNil())
				Expect(err).ToNot(BeNil())
				Expect(err.Error()).To(ContainSubstring("unable to get SPN"))
				Expect(err.Error()).To(ContainSubstring("cannot retrieve AAD token"))
			})
		})

		When("unable to retrieve instance data from IMDS", func() {
			It("should return an error", func() {
				kubeconfigValidator.EXPECT().Validate(kubeconfigPath, false).
					Return(fmt.Errorf("invalid kubeconfig")).
					Times(1)
				aadClient.EXPECT().GetToken(ctx, gomock.Any(), bootstrapConfig.AADResource).
					Return("spToken", nil).
					Times(1)
				imdsClient.EXPECT().GetInstanceData(ctx).
					Return(nil, errors.New("cannot get VM instance data from IMDS")).
					Times(1)

				kubeconfigData, err := bootstrapClient.GetKubeletClientCredential(ctx, bootstrapConfig)
				Expect(kubeconfigData).To(BeNil())
				Expect(err).ToNot(BeNil())
				Expect(err.Error()).To(ContainSubstring("failed to retrieve instance metadata"))
				Expect(err.Error()).To(ContainSubstring("cannot get VM instance data from IMDS"))
			})
		})

		When("unable to retrieve nonce from bootstrap server", func() {
			It("should return an error", func() {
				kubeconfigValidator.EXPECT().Validate(kubeconfigPath, false).
					Return(fmt.Errorf("invalid kubeconfig")).
					Times(1)
				aadClient.EXPECT().GetToken(ctx, gomock.Any(), bootstrapConfig.AADResource).
					Return("spToken", nil).
					Times(1)
				imdsClient.EXPECT().GetInstanceData(ctx).
					Return(&datamodel.VMSSInstanceData{}, nil).
					Times(1)
				serviceClient.EXPECT().GetNonce(ctx, gomock.Any()).
					Return(&secureTLSBootstrapService.NonceResponse{}, errors.New("cannot get nonce response")).
					Times(1)

				kubeconfigData, err := bootstrapClient.GetKubeletClientCredential(ctx, bootstrapConfig)
				Expect(kubeconfigData).To(BeNil())
				Expect(err).ToNot(BeNil())
				Expect(err.Error()).To(ContainSubstring("failed to retrieve a nonce from bootstrap server"))
				Expect(err.Error()).To(ContainSubstring("cannot get nonce response"))
			})
		})

		When("unable to retrieve attested data from IMDS", func() {
			It("should return an error", func() {
				kubeconfigValidator.EXPECT().Validate(kubeconfigPath, false).
					Return(fmt.Errorf("invalid kubeconfig")).
					Times(1)
				aadClient.EXPECT().GetToken(ctx, gomock.Any(), bootstrapConfig.AADResource).
					Return("spToken", nil).
					Times(1)
				imdsClient.EXPECT().GetInstanceData(ctx).
					Return(&datamodel.VMSSInstanceData{}, nil).
					Times(1)
				serviceClient.EXPECT().GetNonce(ctx, gomock.Any()).
					Return(&secureTLSBootstrapService.NonceResponse{
						Nonce: "nonce",
					}, nil).
					Times(1)
				imdsClient.EXPECT().GetAttestedData(ctx, "nonce").
					Return(nil, errors.New("cannot get VM attested data")).
					Times(1)

				kubeconfigData, err := bootstrapClient.GetKubeletClientCredential(ctx, bootstrapConfig)
				Expect(kubeconfigData).To(BeNil())
				Expect(err).ToNot(BeNil())
				Expect(err.Error()).To(ContainSubstring("failed to retrieve attested data"))
				Expect(err.Error()).To(ContainSubstring("cannot get VM attested data"))
			})
		})

		When("unable to retrieve a credential from the bootstrap server", func() {
			It("should return an error", func() {
				kubeconfigValidator.EXPECT().Validate(kubeconfigPath, false).
					Return(fmt.Errorf("invalid kubeconfig")).
					Times(1)
				aadClient.EXPECT().GetToken(ctx, gomock.Any(), bootstrapConfig.AADResource).
					Return("spToken", nil).
					Times(1)
				imdsClient.EXPECT().GetInstanceData(ctx).
					Return(&datamodel.VMSSInstanceData{}, nil).
					Times(1)
				serviceClient.EXPECT().GetNonce(ctx, gomock.Any()).
					Return(&secureTLSBootstrapService.NonceResponse{
						Nonce: "nonce",
					}, nil).
					Times(1)
				imdsClient.EXPECT().GetAttestedData(ctx, "nonce").
					Return(&datamodel.VMSSAttestedData{
						Signature: "signedBlob",
					}, nil).
					Times(1)
				serviceClient.EXPECT().GetCredential(ctx, gomock.Any()).
					Return(nil, errors.New("cannot get credential")).
					Times(1)

				kubeconfigData, err := bootstrapClient.GetKubeletClientCredential(ctx, bootstrapConfig)
				Expect(kubeconfigData).To(BeNil())
				Expect(err).ToNot(BeNil())
				Expect(err.Error()).To(ContainSubstring("failed to retrieve new kubelet client credential from bootstrap server"))
				Expect(err.Error()).To(ContainSubstring("cannot get credential"))
			})
		})

		When("bootstrap server responds with an empty credential", func() {
			It("should return an error", func() {
				kubeconfigValidator.EXPECT().Validate(kubeconfigPath, false).
					Return(fmt.Errorf("invalid kubeconfig")).
					Times(1)
				aadClient.EXPECT().GetToken(ctx, gomock.Any(), bootstrapConfig.AADResource).
					Return("spToken", nil).
					Times(1)
				imdsClient.EXPECT().GetInstanceData(ctx).
					Return(&datamodel.VMSSInstanceData{}, nil).
					Times(1)
				serviceClient.EXPECT().GetNonce(ctx, gomock.Any()).
					Return(&secureTLSBootstrapService.NonceResponse{
						Nonce: "nonce",
					}, nil).
					Times(1)
				imdsClient.EXPECT().GetAttestedData(ctx, "nonce").
					Return(&datamodel.VMSSAttestedData{
						Signature: "signedBlob",
					}, nil).
					Times(1)
				serviceClient.EXPECT().GetCredential(ctx, gomock.Any()).
					Return(&secureTLSBootstrapService.CredentialResponse{
						EncodedCertPEM: "",
					}, nil).
					Times(1)

				kubeconfigData, err := bootstrapClient.GetKubeletClientCredential(ctx, bootstrapConfig)
				Expect(kubeconfigData).To(BeNil())
				Expect(err).ToNot(BeNil())
				Expect(err.Error()).To(ContainSubstring("cert data from bootstrap server is empty"))
			})
		})

		When("bootstrap server responds with an invalid credential", func() {
			It("should return an error", func() {
				kubeconfigValidator.EXPECT().Validate(kubeconfigPath, false).
					Return(fmt.Errorf("invalid kubeconfig")).
					Times(1)
				aadClient.EXPECT().GetToken(ctx, gomock.Any(), bootstrapConfig.AADResource).
					Return("spToken", nil).
					Times(1)
				imdsClient.EXPECT().GetInstanceData(ctx).
					Return(&datamodel.VMSSInstanceData{}, nil).
					Times(1)
				serviceClient.EXPECT().GetNonce(ctx, gomock.Any()).
					Return(&secureTLSBootstrapService.NonceResponse{
						Nonce: "nonce",
					}, nil).
					Times(1)
				imdsClient.EXPECT().GetAttestedData(ctx, "nonce").
					Return(&datamodel.VMSSAttestedData{
						Signature: "signedBlob",
					}, nil).
					Times(1)
				serviceClient.EXPECT().GetCredential(ctx, gomock.Any()).
					Return(&secureTLSBootstrapService.CredentialResponse{
						EncodedCertPEM: "YW55IGNhcm5hbCBwbGVhc3U======",
					}, nil).
					Times(1)

				kubeconfigData, err := bootstrapClient.GetKubeletClientCredential(ctx, bootstrapConfig)
				Expect(kubeconfigData).To(BeNil())
				Expect(err).ToNot(BeNil())
				Expect(err.Error()).To(ContainSubstring("failed to decode cert data from bootstrap server"))
			})
		})

		When("bootstrap server can generate a credential", func() {
			It("should return a new kubeconfig object referencing the new credential", func() {
				clientCertPEM, _, err := testutil.GenerateCertPEMWithExpiration(testutil.CertTemplate{
					CommonName:   "system:node:node",
					Organization: "system:nodes",
					Expiration:   time.Now().Add(time.Hour),
				})
				Expect(err).To(BeNil())
				kubeconfigValidator.EXPECT().Validate(kubeconfigPath, false).
					Return(fmt.Errorf("invalid kubeconfig")).
					Times(1)
				aadClient.EXPECT().GetToken(ctx, gomock.Any(), bootstrapConfig.AADResource).
					Return("spToken", nil).
					Times(1)
				imdsClient.EXPECT().GetInstanceData(ctx).
					Return(&datamodel.VMSSInstanceData{
						Compute: datamodel.Compute{
							ResourceID: "resourceId",
						},
					}, nil).
					Times(1)
				serviceClient.EXPECT().GetNonce(ctx, gomock.Any()).
					Return(&secureTLSBootstrapService.NonceResponse{
						Nonce: "nonce",
					}, nil).
					Times(1)
				imdsClient.EXPECT().GetAttestedData(ctx, "nonce").
					Return(&datamodel.VMSSAttestedData{
						Signature: "signedBlob",
					}, nil).
					Times(1)
				serviceClient.EXPECT().GetCredential(ctx, gomock.Any()).
					Return(&secureTLSBootstrapService.CredentialResponse{
						EncodedCertPEM: base64.StdEncoding.EncodeToString(clientCertPEM),
					}, nil).
					Times(1)

				kubeconfigData, err := bootstrapClient.GetKubeletClientCredential(ctx, bootstrapConfig)
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
				Expect(certData).ToNot(BeEmpty())

				keyData, err := os.ReadFile(bootstrapConfig.KeyFilePath)
				Expect(err).To(BeNil())
				Expect(keyData).ToNot(BeEmpty())
			})
		})
	})
})
