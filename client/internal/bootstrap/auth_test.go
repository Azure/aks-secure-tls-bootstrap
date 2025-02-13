// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package bootstrap

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"go.uber.org/mock/gomock"
	"go.uber.org/zap"

	aadmocks "github.com/Azure/aks-secure-tls-bootstrap/client/internal/aad/mocks"
	"github.com/Azure/aks-secure-tls-bootstrap/client/internal/datamodel"
	imdsmocks "github.com/Azure/aks-secure-tls-bootstrap/client/internal/imds/mocks"
)

var _ = Describe("Auth", Ordered, func() {
	var (
		mockCtrl        *gomock.Controller
		imdsClient      *imdsmocks.MockClient
		aadClient       *aadmocks.MockClient
		bootstrapClient *Client
		logger          *zap.Logger
	)

	BeforeAll(func() {
		logger, _ = zap.NewDevelopment()
	})

	BeforeEach(func() {
		mockCtrl = gomock.NewController(GinkgoT())
		imdsClient = imdsmocks.NewMockClient(mockCtrl)
		aadClient = aadmocks.NewMockClient(mockCtrl)
		bootstrapClient = &Client{
			logger:     logger,
			imdsClient: imdsClient,
			aadClient:  aadClient,
		}
	})

	AfterEach(func() {
		mockCtrl.Finish()
	})

	Context("getAuthToken", func() {
		var (
			emptyClientID = ""
			resource      = "resource"
		)

		When("customClientID is not supplied", func() {
			When("azure config is nil", func() {
				It("should return an error", func() {
					var azureConfig *datamodel.AzureConfig
					ctx, cancel := context.WithCancel(context.Background())
					defer cancel()

					token, err := bootstrapClient.getAuthToken(ctx, emptyClientID, resource, azureConfig)
					Expect(token).To(BeEmpty())
					Expect(err).ToNot(BeNil())
					Expect(err.Error()).To(ContainSubstring("unable to get auth token: azure config is nil"))
				})
			})

			When("azure config is missing clientId", func() {
				It("should return an error", func() {
					imdsClient.EXPECT().GetMSIToken(
						gomock.Any(),
						gomock.Any(),
						gomock.Any(),
					).Times(0)
					aadClient.EXPECT().GetToken(
						gomock.Any(),
						gomock.Any(),
						gomock.Any(),
					).Times(0)
					azureConfig := &datamodel.AzureConfig{
						ClientSecret: "secret",
						TenantID:     "tid",
					}
					ctx, cancel := context.WithCancel(context.Background())
					defer cancel()

					token, err := bootstrapClient.getAuthToken(ctx, emptyClientID, resource, azureConfig)
					Expect(token).To(BeEmpty())
					Expect(err).ToNot(BeNil())
					Expect(err.Error()).To(ContainSubstring("unable to infer node identity type: client ID in azure.json is empty"))
				})
			})

			When("azure config has clientId but is missing clientSecret", func() {
				It("should return an error", func() {
					imdsClient.EXPECT().GetMSIToken(
						gomock.Any(),
						gomock.Any(),
						gomock.Any(),
					).Times(0)
					aadClient.EXPECT().GetToken(
						gomock.Any(),
						gomock.Any(),
						gomock.Any(),
					).Times(0)
					azureConfig := &datamodel.AzureConfig{
						ClientID: "cid",
						TenantID: "tid",
					}
					ctx, cancel := context.WithCancel(context.Background())
					defer cancel()

					token, err := bootstrapClient.getAuthToken(ctx, emptyClientID, resource, azureConfig)
					Expect(token).To(BeEmpty())
					Expect(err).ToNot(BeNil())
					Expect(err.Error()).To(ContainSubstring("cannot retrieve SP token from AAD: azure.json missing clientSecret"))
				})
			})

			When("azure config has clientId and clientSecret but is missing tenantId", func() {
				It("should return an error", func() {
					imdsClient.EXPECT().GetMSIToken(
						gomock.Any(),
						gomock.Any(),
						gomock.Any(),
					).Times(0)
					aadClient.EXPECT().GetToken(
						gomock.Any(),
						gomock.Any(),
						gomock.Any(),
					).Times(0)
					azureConfig := &datamodel.AzureConfig{
						ClientID:     "cid",
						ClientSecret: "secret",
					}
					ctx, cancel := context.WithCancel(context.Background())
					defer cancel()

					token, err := bootstrapClient.getAuthToken(ctx, emptyClientID, resource, azureConfig)
					Expect(token).To(BeEmpty())
					Expect(err).ToNot(BeNil())
					Expect(err.Error()).To(ContainSubstring("cannot retrieve SP token from AAD: azure.json missing tenantId"))
				})
			})

			When("azure config contains msi clientId and userAssignedIdentityId is non-empty", func() {
				It("should acquire MSI token from IMDS using userAssignedIdentityId as clientId", func() {
					userAssignedIdentityID := "uami"
					imdsClient.EXPECT().GetMSIToken(gomock.Any(), userAssignedIdentityID, resource).
						Return("mockMSIToken", nil).
						Times(1)
					aadClient.EXPECT().GetToken(
						gomock.Any(),
						gomock.Any(),
						gomock.Any(),
					).Times(0)
					azureConfigWithMSI := &datamodel.AzureConfig{
						ClientID:               "msi",
						UserAssignedIdentityID: userAssignedIdentityID,
					}
					ctx, cancel := context.WithCancel(context.Background())
					defer cancel()

					msiToken, err := bootstrapClient.getAuthToken(ctx, emptyClientID, resource, azureConfigWithMSI)
					Expect(err).To(BeNil())
					Expect(msiToken).To(Equal("mockMSIToken"))
				})
			})

			When("azure config contains msi clientId and userAssignedIdentityId is empty", func() {
				It("should acquire MSI token from IMDS without specifying clientId", func() {
					imdsClient.EXPECT().GetMSIToken(gomock.Any(), emptyClientID, resource).
						Return("mockMSIToken", nil).
						Times(1)
					aadClient.EXPECT().GetToken(
						gomock.Any(),
						gomock.Any(),
						gomock.Any(),
					).Times(0)
					azureConfigWithMSI := &datamodel.AzureConfig{
						ClientID: "msi",
					}
					ctx, cancel := context.WithCancel(context.Background())
					defer cancel()

					msiToken, err := bootstrapClient.getAuthToken(ctx, emptyClientID, resource, azureConfigWithMSI)
					Expect(err).To(BeNil())
					Expect(msiToken).To(Equal("mockMSIToken"))
				})
			})

			When("azure config contains non-MSI clientId", func() {
				It("should use service principal and acquire token from AAD", func() {
					azureConfigSPN := &datamodel.AzureConfig{
						ClientID:     "clientId",
						ClientSecret: "clientSecret",
						TenantID:     "tenantId",
					}
					aadClient.EXPECT().GetToken(gomock.Any(), azureConfigSPN, resource).
						Return("spToken", nil).
						Times(1)
					imdsClient.EXPECT().GetMSIToken(
						gomock.Any(),
						gomock.Any(),
						gomock.Any(),
					).Times(0)
					ctx, cancel := context.WithCancel(context.Background())
					defer cancel()

					spToken, err := bootstrapClient.getAuthToken(ctx, emptyClientID, resource, azureConfigSPN)
					Expect(err).To(BeNil())
					Expect(spToken).To(Equal("spToken"))
				})
			})
		})

		When("customClientID is supplied", func() {
			var nonEmptyClientID = "clientId"

			It("should acquire MSI token from IMDS", func() {
				imdsClient.EXPECT().GetMSIToken(gomock.Any(), nonEmptyClientID, resource).
					Return("mockMSIToken", nil).
					Times(1)
				aadClient.EXPECT().GetToken(
					gomock.Any(),
					gomock.Any(),
					gomock.Any(),
				).Times(0)
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()

				token, err := bootstrapClient.getAuthToken(ctx, nonEmptyClientID, resource, nil)
				Expect(err).To(BeNil())
				Expect(token).To(Equal("mockMSIToken"))
			})
		})
	})
})
