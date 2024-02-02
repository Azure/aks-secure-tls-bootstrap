// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package client

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	aadmocks "github.com/Azure/aks-secure-tls-bootstrap/client/pkg/aad/mocks"
	"github.com/Azure/aks-secure-tls-bootstrap/client/pkg/datamodel"
	imdsmocks "github.com/Azure/aks-secure-tls-bootstrap/client/pkg/imds/mocks"
	kubeconfigmocks "github.com/Azure/aks-secure-tls-bootstrap/client/pkg/kubeconfig/mocks"
	"github.com/Azure/aks-secure-tls-bootstrap/client/pkg/testutil"
	utilmocks "github.com/Azure/aks-secure-tls-bootstrap/client/pkg/util/mocks"
	secureTLSBootstrapService "github.com/Azure/aks-secure-tls-bootstrap/service/protos"
	servicemocks "github.com/Azure/aks-secure-tls-bootstrap/service/protos/mocks"
	. "github.com/onsi/ginkgo"
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
	)
	var (
		mockCtrl            *gomock.Controller
		imdsClient          *imdsmocks.MockClient
		aadClient           *aadmocks.MockClient
		kubeconfigValidator *kubeconfigmocks.MockValidator
		serviceClient       *servicemocks.MockSecureTLSBootstrapServiceClient
		bootstrapClient     *SecureTLSBootstrapClient
		fs                  *utilmocks.MockFS
	)

	clusterCACertPEM, _, err := testutil.GenerateCertPEMWithExpiration("hcp", "aks", time.Now().Add(time.Hour))
	Expect(err).To(BeNil())

	defaultAzureConfig := &datamodel.AzureConfig{
		ClientID:     "clientId",
		ClientSecret: "clientSecret",
		TenantID:     "tenantId",
	}

	defaultOpts := &GetKubeletClientCredentialOpts{
		ClusterCAFilePath: defaultClusterCAFilePath,
		APIServerFQDN:     defaultAPIServerFQDN,
		KubeconfigPath:    defaultKubeconfigPath,
	}

	Context("NewSecureTLSBootstrapClient", func() {
		BeforeEach(func() {
			mockCtrl = gomock.NewController(GinkgoT())
			fs = utilmocks.NewMockFS(mockCtrl)
		})

		AfterEach(func() {
			mockCtrl.Finish()
		})

		When("azure config cannot be loaded", func() {
			It("should return an error", func() {
				fs.EXPECT().ReadFile(gomock.Any()).
					Return(nil, fmt.Errorf("azure config does not exist")).
					Times(1)

				newClient, err := NewSecureTLSBootstrapClient(fs, logger)
				Expect(newClient).To(BeNil())
				Expect(err).ToNot(BeNil())
				Expect(err.Error()).To(ContainSubstring("failed to load azure config"))
				Expect(err.Error()).To(ContainSubstring("azure config does not exist"))
			})
		})

		When("azure config exists and can be loaded", func() {
			It("should return a new bootstrap client", func() {
				azureConfigBytes, err := json.Marshal(defaultAzureConfig)
				Expect(err).To(BeNil())
				fs.EXPECT().ReadFile(gomock.Any()).
					Return(azureConfigBytes, nil).
					Times(1)

				newClient, err := NewSecureTLSBootstrapClient(fs, logger)
				Expect(err).To(BeNil())
				Expect(newClient).ToNot(BeNil())
				Expect(newClient.azureConfig.ClientID).To(Equal("clientId"))
				Expect(newClient.azureConfig.ClientSecret).To(Equal("clientSecret"))
				Expect(newClient.azureConfig.TenantID).To(Equal("tenantId"))
			})
		})
	})

	Context("GetKubeletClientCredential", func() {
		BeforeEach(func() {
			mockCtrl = gomock.NewController(GinkgoT())
			imdsClient = imdsmocks.NewMockClient(mockCtrl)
			aadClient = aadmocks.NewMockClient(mockCtrl)
			kubeconfigValidator = kubeconfigmocks.NewMockValidator(mockCtrl)
			serviceClient = servicemocks.NewMockSecureTLSBootstrapServiceClient(mockCtrl)
			fs = utilmocks.NewMockFS(mockCtrl)

			bootstrapClient = &SecureTLSBootstrapClient{
				logger:              logger,
				imdsClient:          imdsClient,
				aadClient:           aadClient,
				kubeconfigValidator: kubeconfigValidator,
				azureConfig:         defaultAzureConfig,
				fs:                  fs,
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
				fs.EXPECT().ReadFile(gomock.Any()).Times(0)
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
				fs.EXPECT().ReadFile(defaultOpts.ClusterCAFilePath).
					Return(clusterCACertPEM, nil).
					Times(1)
				aadClient.EXPECT().GetToken(ctx, gomock.Any(), defaultOpts.AADResource).
					Return("", errors.New("cannot retrieve AAD token")).
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
				fs.EXPECT().ReadFile(defaultOpts.ClusterCAFilePath).
					Return(clusterCACertPEM, nil).
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
				fs.EXPECT().ReadFile(defaultOpts.ClusterCAFilePath).
					Return(clusterCACertPEM, nil).
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
				fs.EXPECT().ReadFile(defaultOpts.ClusterCAFilePath).
					Return(clusterCACertPEM, nil).
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
				fs.EXPECT().ReadFile(defaultOpts.ClusterCAFilePath).
					Return(clusterCACertPEM, nil).
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
				fs.EXPECT().ReadFile(defaultOpts.ClusterCAFilePath).
					Return(clusterCACertPEM, nil).
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
				fs.EXPECT().ReadFile(defaultOpts.ClusterCAFilePath).
					Return(clusterCACertPEM, nil).
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
				clientCertPEM, _, err := testutil.GenerateCertPEMWithExpiration("system:nodes:node", "system:nodes", time.Now().Add(time.Hour))
				Expect(err).To(BeNil())
				kubeconfigValidator.EXPECT().Validate(defaultKubeconfigPath, false).
					Return(fmt.Errorf("invalid kubeconfig")).
					Times(1)
				fs.EXPECT().ReadFile(defaultOpts.ClusterCAFilePath).
					Return(clusterCACertPEM, nil).
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
				Expect(defaultCluster.CertificateAuthority).To(Equal(defaultOpts.ClusterCAFilePath))

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
		Context("Validate", func() {
			var opts *GetKubeletClientCredentialOpts

			BeforeEach(func() {
				opts = &GetKubeletClientCredentialOpts{
					ClusterCAFilePath: "path",
					APIServerFQDN:     "fqdn",
					CustomClientID:    "clientId",
					NextProto:         "alpn",
					AADResource:       "appID",
					KubeconfigPath:    "path",
				}
			})

			When("ClusterCAFile is empty", func() {
				It("should return an error", func() {
					opts.ClusterCAFilePath = ""
					err := opts.Validate()
					Expect(err).ToNot(BeNil())
					Expect(err.Error()).To(ContainSubstring("cluster CA file must be specified"))
				})
			})

			When("APIServerFQDN is empty", func() {
				It("should return an error", func() {
					opts.APIServerFQDN = ""
					err := opts.Validate()
					Expect(err).ToNot(BeNil())
					Expect(err.Error()).To(ContainSubstring("apiserver FQDN must be specified"))
				})
			})

			When("NextProto is empty", func() {
				It("should return an error", func() {
					opts.NextProto = ""
					err := opts.Validate()
					Expect(err).ToNot(BeNil())
					Expect(err.Error()).To(ContainSubstring("next proto header value must be specified"))
				})
			})

			When("AADResource is empty", func() {
				It("should return an error", func() {
					opts.AADResource = ""
					err := opts.Validate()
					Expect(err).ToNot(BeNil())
					Expect(err.Error()).To(ContainSubstring("AAD resource must be specified"))
				})
			})

			When("KubeconfigPath is empty", func() {
				It("should return an error", func() {
					opts.KubeconfigPath = ""
					err := opts.Validate()
					Expect(err).ToNot(BeNil())
					Expect(err.Error()).To(ContainSubstring("kubeconfig must be specified"))
				})
			})

			When("client opts are valid", func() {
				It("should validagte without error", func() {
					err := opts.Validate()
					Expect(err).To(BeNil())
				})
			})
		})
	})
})
