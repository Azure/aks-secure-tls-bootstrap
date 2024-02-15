// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package client

import (
	"context"
	"encoding/base64"
	"encoding/json"
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

var _ = Describe("SecureTLSBootstrapClient tests", func() {
	const (
		emptyJSON                = "{}"
		defaultAPIServerFQDN     = "https://controlplane.azmk8s.io"
		defaultClusterCAFilePath = "path/to/ca.crt"
		defaultKubeconfigPath    = "path/to/kubeconfig"
		defaultAzureConfigPath   = "path/to/azure.json"
	)
	var (
		mockCtrl            *gomock.Controller
		imdsClient          *imdsmocks.MockClient
		aadClient           *aadmocks.MockClient
		kubeconfigValidator *kubeconfigmocks.MockValidator
		serviceClient       *servicemocks.MockSecureTLSBootstrapServiceClient
		bootstrapClient     *SecureTLSBootstrapClient
	)
	defaultOpts := &GetKubeletClientCredentialOpts{
		NextProto:      "bootstrap",
		ClusterCAData:  clusterCACertPEM,
		APIServerFQDN:  defaultAPIServerFQDN,
		KubeconfigPath: defaultKubeconfigPath,
		AzureConfig: &datamodel.AzureConfig{
			ClientID:     "clientId",
			ClientSecret: "clientSecret",
			TenantID:     "tenantId",
		},
	}

	Context("NewSecureTLSBootstrapClient", func() {
		It("should return a new bootstrap client", func() {
			newClient, err := NewSecureTLSBootstrapClient(logger)
			Expect(err).To(BeNil())
			Expect(newClient).ToNot(BeNil())
			Expect(newClient.logger).ToNot(BeNil())
			Expect(newClient.serviceClientFactory).ToNot(BeNil())
			Expect(newClient.aadClient).ToNot(BeNil())
			Expect(newClient.imdsClient).ToNot(BeNil())
			Expect(newClient.kubeconfigValidator).ToNot(BeNil())
		})
	})

	Context("GetKubeletClientCredential", func() {
		BeforeEach(func() {
			mockCtrl = gomock.NewController(GinkgoT())
			imdsClient = imdsmocks.NewMockClient(mockCtrl)
			aadClient = aadmocks.NewMockClient(mockCtrl)
			kubeconfigValidator = kubeconfigmocks.NewMockValidator(mockCtrl)
			serviceClient = servicemocks.NewMockSecureTLSBootstrapServiceClient(mockCtrl)

			bootstrapClient = &SecureTLSBootstrapClient{
				logger:              logger,
				imdsClient:          imdsClient,
				aadClient:           aadClient,
				kubeconfigValidator: kubeconfigValidator,
			}
			bootstrapClient.serviceClientFactory = func(
				ctx context.Context,
				logger *zap.Logger,
				opts serviceClientFactoryOpts) (secureTLSBootstrapService.SecureTLSBootstrapServiceClient, *grpc.ClientConn, error) {
				return serviceClient, nil, nil
			}
		})

		AfterEach(func() {
			mockCtrl.Finish()
		})

		When("specified kubeconfig is already valid", func() {
			It("should peform a no-op", func() {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				kubeconfigValidator.EXPECT().Validate(defaultKubeconfigPath, false).
					Return(nil).
					Times(1)
				serviceClient.EXPECT().GetCredential(gomock.Any(), gomock.Any()).Times(0)
				serviceClient.EXPECT().GetNonce(gomock.Any(), gomock.Any()).Times(0)
				imdsClient.EXPECT().GetAttestedData(gomock.Any(), gomock.Any()).Times(0)
				imdsClient.EXPECT().GetInstanceData(gomock.Any()).Times(0)
				imdsClient.EXPECT().GetMSIToken(gomock.Any(), gomock.Any(), gomock.Any()).Times(0)
				aadClient.EXPECT().GetToken(gomock.Any(), gomock.Any(), gomock.Any()).Times(0)

				kubeconfigData, err := bootstrapClient.GetKubeletClientCredential(ctx, defaultOpts)
				Expect(err).To(BeNil())
				Expect(kubeconfigData).To(BeNil())
			})
		})

		When("an auth token cannot be retrieved", func() {
			It("return an error", func() {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				kubeconfigValidator.EXPECT().Validate(defaultKubeconfigPath, false).
					Return(fmt.Errorf("invalid kubeconfig")).
					Times(1)
				aadClient.EXPECT().GetToken(ctx, gomock.Any(), defaultOpts.AADResource).
					Return("", fmt.Errorf("cannot retrieve AAD token")).
					Times(1)

				kubeconfigData, err := bootstrapClient.GetKubeletClientCredential(ctx, defaultOpts)
				Expect(kubeconfigData).To(BeNil())
				Expect(err).ToNot(BeNil())
				Expect(err.Error()).To(ContainSubstring("unable to get SPN"))
				Expect(err.Error()).To(ContainSubstring("cannot retrieve AAD token"))
			})
		})

		When("unable to retrieve instance data from IMDS", func() {
			It("should return an error", func() {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				kubeconfigValidator.EXPECT().Validate(defaultKubeconfigPath, false).
					Return(fmt.Errorf("invalid kubeconfig")).
					Times(1)
				aadClient.EXPECT().GetToken(ctx, gomock.Any(), defaultOpts.AADResource).
					Return("spToken", nil).
					Times(1)
				imdsClient.EXPECT().GetInstanceData(ctx).
					Return(nil, errors.New("cannot get VM instance data from IMDS")).
					Times(1)

				kubeconfigData, err := bootstrapClient.GetKubeletClientCredential(ctx, defaultOpts)
				Expect(kubeconfigData).To(BeNil())
				Expect(err).ToNot(BeNil())
				Expect(err.Error()).To(ContainSubstring("failed to retrieve instance metadata"))
				Expect(err.Error()).To(ContainSubstring("cannot get VM instance data from IMDS"))
			})
		})

		When("unable to retrieve nonce from bootstrap server", func() {
			It("should return an error", func() {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				kubeconfigValidator.EXPECT().Validate(defaultKubeconfigPath, false).
					Return(fmt.Errorf("invalid kubeconfig")).
					Times(1)
				aadClient.EXPECT().GetToken(ctx, gomock.Any(), defaultOpts.AADResource).
					Return("spToken", nil).
					Times(1)
				imdsClient.EXPECT().GetInstanceData(ctx).
					Return(&datamodel.VMSSInstanceData{}, nil).
					Times(1)
				serviceClient.EXPECT().GetNonce(ctx, gomock.Any()).
					Return(&secureTLSBootstrapService.NonceResponse{}, errors.New("cannot get nonce response")).
					Times(1)

				kubeconfigData, err := bootstrapClient.GetKubeletClientCredential(ctx, defaultOpts)
				Expect(kubeconfigData).To(BeNil())
				Expect(err).ToNot(BeNil())
				Expect(err.Error()).To(ContainSubstring("failed to retrieve a nonce from bootstrap server"))
				Expect(err.Error()).To(ContainSubstring("cannot get nonce response"))
			})
		})

		When("unable to retrieve attested data from IMDS", func() {
			It("should return an error", func() {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				kubeconfigValidator.EXPECT().Validate(defaultKubeconfigPath, false).
					Return(fmt.Errorf("invalid kubeconfig")).
					Times(1)
				aadClient.EXPECT().GetToken(ctx, gomock.Any(), defaultOpts.AADResource).
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

				kubeconfigData, err := bootstrapClient.GetKubeletClientCredential(ctx, defaultOpts)
				Expect(kubeconfigData).To(BeNil())
				Expect(err).ToNot(BeNil())
				Expect(err.Error()).To(ContainSubstring("failed to retrieve attested data"))
				Expect(err.Error()).To(ContainSubstring("cannot get VM attested data"))
			})
		})

		When("unable to retrieve a credential from the bootstrap server", func() {
			It("should return an error", func() {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				kubeconfigValidator.EXPECT().Validate(defaultKubeconfigPath, false).
					Return(fmt.Errorf("invalid kubeconfig")).
					Times(1)
				aadClient.EXPECT().GetToken(ctx, gomock.Any(), defaultOpts.AADResource).
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

				kubeconfigData, err := bootstrapClient.GetKubeletClientCredential(ctx, defaultOpts)
				Expect(kubeconfigData).To(BeNil())
				Expect(err).ToNot(BeNil())
				Expect(err.Error()).To(ContainSubstring("failed to retrieve new kubelet client credential from bootstrap server"))
				Expect(err.Error()).To(ContainSubstring("cannot get credential"))
			})
		})

		When("bootstrap server responds with an empty credential", func() {
			It("should return an error", func() {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				kubeconfigValidator.EXPECT().Validate(defaultKubeconfigPath, false).
					Return(fmt.Errorf("invalid kubeconfig")).
					Times(1)
				aadClient.EXPECT().GetToken(ctx, gomock.Any(), defaultOpts.AADResource).
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

				kubeconfigData, err := bootstrapClient.GetKubeletClientCredential(ctx, defaultOpts)
				Expect(kubeconfigData).To(BeNil())
				Expect(err).ToNot(BeNil())
				Expect(err.Error()).To(ContainSubstring("cert data from bootstrap server is empty"))
			})
		})

		When("bootstrap server responds with an invalid credential", func() {
			It("should return an error", func() {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				kubeconfigValidator.EXPECT().Validate(defaultKubeconfigPath, false).
					Return(fmt.Errorf("invalid kubeconfig")).
					Times(1)
				aadClient.EXPECT().GetToken(ctx, gomock.Any(), defaultOpts.AADResource).
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

				kubeconfigData, err := bootstrapClient.GetKubeletClientCredential(ctx, defaultOpts)
				Expect(kubeconfigData).To(BeNil())
				Expect(err).ToNot(BeNil())
				Expect(err.Error()).To(ContainSubstring("failed to decode cert data from bootstrap server"))
			})
		})

		When("bootstrap server can generate a credential", func() {
			It("should return a new kubeconfig object with the credential embedded", func() {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				clientCertPEM, _, err := testutil.GenerateCertPEMWithExpiration("system:node:node", "system:nodes", time.Now().Add(time.Hour))
				Expect(err).To(BeNil())
				kubeconfigValidator.EXPECT().Validate(defaultKubeconfigPath, false).
					Return(fmt.Errorf("invalid kubeconfig")).
					Times(1)
				aadClient.EXPECT().GetToken(ctx, gomock.Any(), defaultOpts.AADResource).
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

				kubeconfigData, err := bootstrapClient.GetKubeletClientCredential(ctx, defaultOpts)
				Expect(err).To(BeNil())
				Expect(kubeconfigData).ToNot(BeNil())

				Expect(kubeconfigData.Clusters).To(HaveKey("default-cluster"))
				defaultCluster := kubeconfigData.Clusters["default-cluster"]
				Expect(defaultCluster.Server).To(Equal(defaultOpts.APIServerFQDN))
				Expect(defaultCluster.CertificateAuthorityData).To(Equal(defaultOpts.ClusterCAData))

				Expect(kubeconfigData.AuthInfos).To(HaveKey("default-auth"))
				defaultAuth := kubeconfigData.AuthInfos["default-auth"]
				Expect(defaultAuth.ClientCertificateData).To(Equal(clientCertPEM))
				Expect(defaultAuth.ClientKeyData).ToNot(BeEmpty())

				Expect(kubeconfigData.Contexts).To(HaveKey("default-context"))
				defaultContext := kubeconfigData.Contexts["default-context"]
				Expect(defaultContext.Cluster).To(Equal("default-cluster"))
				Expect(defaultContext.AuthInfo).To(Equal("default-auth"))

				Expect(kubeconfigData.CurrentContext).To(Equal("default-context"))
			})
		})
	})

	Context("GetKubeletClientCredentialOpts tests", func() {
		Context("ValidateAndSet", func() {
			var opts *GetKubeletClientCredentialOpts
			defaultAzureConfigPath := "path/to/azure.json"
			defaultClusterCAFilePath := "path/to/ca.crt"

			BeforeEach(func() {
				opts = &GetKubeletClientCredentialOpts{
					APIServerFQDN:  "fqdn",
					CustomClientID: "clientId",
					NextProto:      "alpn",
					AADResource:    "appID",
					KubeconfigPath: "path",
				}
			})

			When("clusterCAFilePath is empty", func() {
				It("should return an error", func() {
					emptyClusterCAFilePath := ""
					err := opts.ValidateAndSet(defaultAzureConfigPath, emptyClusterCAFilePath)
					Expect(err).ToNot(BeNil())
					Expect(err.Error()).To(ContainSubstring("cluster CA file path must be specified"))
				})
			})

			When("azureConfigPath is empty", func() {
				It("should return an error", func() {
					emptyAzureConfigPath := ""
					err := opts.ValidateAndSet(emptyAzureConfigPath, defaultClusterCAFilePath)
					Expect(err).ToNot(BeNil())
					Expect(err.Error()).To(ContainSubstring("azure config path must be specified"))
				})
			})

			When("APIServerFQDN is empty", func() {
				It("should return an error", func() {
					opts.APIServerFQDN = ""
					err := opts.ValidateAndSet(defaultAzureConfigPath, defaultClusterCAFilePath)
					Expect(err).ToNot(BeNil())
					Expect(err.Error()).To(ContainSubstring("apiserver FQDN must be specified"))
				})
			})

			When("NextProto is empty", func() {
				It("should return an error", func() {
					opts.NextProto = ""
					err := opts.ValidateAndSet(defaultAzureConfigPath, defaultClusterCAFilePath)
					Expect(err).ToNot(BeNil())
					Expect(err.Error()).To(ContainSubstring("next proto header value must be specified"))
				})
			})

			When("AADResource is empty", func() {
				It("should return an error", func() {
					opts.AADResource = ""
					err := opts.ValidateAndSet(defaultAzureConfigPath, defaultClusterCAFilePath)
					Expect(err).ToNot(BeNil())
					Expect(err.Error()).To(ContainSubstring("AAD resource must be specified"))
				})
			})

			When("KubeconfigPath is empty", func() {
				It("should return an error", func() {
					opts.KubeconfigPath = ""
					err := opts.ValidateAndSet(defaultAzureConfigPath, defaultClusterCAFilePath)
					Expect(err).ToNot(BeNil())
					Expect(err.Error()).To(ContainSubstring("kubeconfig must be specified"))
				})
			})

			When("client opts are valid", func() {
				It("should validate without error", func() {
					tempDir := GinkgoT().TempDir()
					clusterCAFilePath := filepath.Join(tempDir, "ca.crt")
					err := os.WriteFile(clusterCAFilePath, clusterCACertPEM, os.ModePerm)
					Expect(err).To(BeNil())
					azureConfigPath := filepath.Join(tempDir, "azure.json")
					azureConfigBytes, err := json.Marshal(defaultOpts.AzureConfig)
					Expect(err).To(BeNil())
					err = os.WriteFile(azureConfigPath, azureConfigBytes, os.ModePerm)
					Expect(err).To(BeNil())

					err = opts.ValidateAndSet(azureConfigPath, clusterCAFilePath)
					Expect(err).To(BeNil())
				})
			})
		})
	})
})
