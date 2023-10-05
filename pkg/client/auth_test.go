// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package client

import (
	"context"

	"github.com/Azure/aks-tls-bootstrap-client/pkg/client/mocks"
	"github.com/Azure/aks-tls-bootstrap-client/pkg/datamodel"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"go.uber.org/mock/gomock"
)

var _ = Describe("Auth tests", func() {
	var (
		mockCtrl           *gomock.Controller
		imdsClient         *mocks.MockImdsClient
		aadClient          *mocks.MockAadClient
		tlsBootstrapClient *tlsBootstrapClientImpl
	)

	BeforeEach(func() {
		mockCtrl = gomock.NewController(GinkgoT())
		imdsClient = mocks.NewMockImdsClient(mockCtrl)
		aadClient = mocks.NewMockAadClient(mockCtrl)
		tlsBootstrapClient = &tlsBootstrapClientImpl{
			logger:     testLogger,
			imdsClient: imdsClient,
			aadClient:  aadClient,
		}
	})

	AfterEach(func() {
		mockCtrl.Finish()
	})

	Context("Test getAuthToken", func() {
		var (
			emptyClientID = ""
			resource      = "resource"
		)

		When("userSpecifiedClientID is not supplied", func() {
			When("azure config is nil", func() {
				It("should return an error", func() {
					var azureConfig *datamodel.AzureConfig
					ctx, cancel := context.WithCancel(context.Background())
					defer cancel()

					token, err := tlsBootstrapClient.getAuthToken(ctx, emptyClientID, resource, azureConfig)
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
						gomock.Any(),
					).Times(0)
					aadClient.EXPECT().GetAadToken(
						gomock.Any(),
						gomock.Any(),
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

					spToken, err := tlsBootstrapClient.getAuthToken(ctx, emptyClientID, resource, azureConfig)
					Expect(spToken).To(BeEmpty())
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
						gomock.Any(),
					).Times(0)
					aadClient.EXPECT().GetAadToken(
						gomock.Any(),
						gomock.Any(),
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

					spToken, err := tlsBootstrapClient.getAuthToken(ctx, emptyClientID, resource, azureConfig)
					Expect(spToken).To(BeEmpty())
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
						gomock.Any(),
					).Times(0)
					aadClient.EXPECT().GetAadToken(
						gomock.Any(),
						gomock.Any(),
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

					spToken, err := tlsBootstrapClient.getAuthToken(ctx, emptyClientID, resource, azureConfig)
					Expect(spToken).To(BeEmpty())
					Expect(err).ToNot(BeNil())
					Expect(err.Error()).To(ContainSubstring("cannot retrieve SP token from AAD: azure.json missing tenantId"))
				})
			})

			When("azure config contains msi clientId and userAssignedIdentityId is non-empty", func() {
				It("should acquire MSI token from IMDS using userAssignedIdentityId as clientId", func() {
					userAssignedIdentityID := "uami"
					imdsClient.EXPECT().GetMSIToken(gomock.Any(), baseImdsURL, userAssignedIdentityID, resource).Return(
						&datamodel.AADTokenResponse{
							AccessToken: "mockMSIToken",
						}, nil,
					).Times(1)
					aadClient.EXPECT().GetAadToken(
						gomock.Any(),
						gomock.Any(),
						gomock.Any(),
						gomock.Any(),
						gomock.Any(),
					).Times(0)
					azureConfigMsi := &datamodel.AzureConfig{
						ClientID:               "msi",
						UserAssignedIdentityID: userAssignedIdentityID,
					}

					ctx, cancel := context.WithCancel(context.Background())
					defer cancel()

					msiToken, err := tlsBootstrapClient.getAuthToken(ctx, emptyClientID, resource, azureConfigMsi)
					Expect(err).To(BeNil())
					Expect(msiToken).To(Equal("mockMSIToken"))
				})
			})

			When("azure config contains msi clientId and userAssignedIdentityId is empty", func() {
				It("should acquire MSI token from IMDS without specifying clientId", func() {
					imdsClient.EXPECT().GetMSIToken(gomock.Any(), baseImdsURL, emptyClientID, resource).Return(
						&datamodel.AADTokenResponse{
							AccessToken: "mockMSIToken",
						}, nil,
					).Times(1)
					aadClient.EXPECT().GetAadToken(
						gomock.Any(),
						gomock.Any(),
						gomock.Any(),
						gomock.Any(),
						gomock.Any(),
					).Times(0)
					azureConfigMsi := &datamodel.AzureConfig{
						ClientID: "msi",
					}

					ctx, cancel := context.WithCancel(context.Background())
					defer cancel()

					msiToken, err := tlsBootstrapClient.getAuthToken(ctx, emptyClientID, resource, azureConfigMsi)
					Expect(err).To(BeNil())
					Expect(msiToken).To(Equal("mockMSIToken"))
				})
			})

			When("azure config contains non-MSI clientId", func() {
				It("should use service principal and acquire token from AAD", func() {
					aadClient.EXPECT().GetAadToken(gomock.Any(), "clientId", "clientSecret", "tenantId", resource).Return(
						"spToken",
						nil,
					).Times(1)
					imdsClient.EXPECT().GetMSIToken(
						gomock.Any(),
						gomock.Any(),
						gomock.Any(),
						gomock.Any(),
					).Times(0)
					azureConfigNoMsi := &datamodel.AzureConfig{
						ClientID:     "clientId",
						ClientSecret: "clientSecret",
						TenantID:     "tenantId",
					}

					ctx, cancel := context.WithCancel(context.Background())
					defer cancel()

					spToken, err := tlsBootstrapClient.getAuthToken(ctx, emptyClientID, resource, azureConfigNoMsi)
					Expect(err).To(BeNil())
					Expect(spToken).To(Equal("spToken"))
				})
			})
		})

		When("userSpecifiedClientID is supplied", func() {
			var nonEmptyClientID = "clientId"

			It("should acquire MSI token from IMDS", func() {
				imdsClient.EXPECT().GetMSIToken(gomock.Any(), baseImdsURL, nonEmptyClientID, resource).Return(
					&datamodel.AADTokenResponse{
						AccessToken: "mockMSIToken",
					}, nil,
				).Times(1)
				aadClient.EXPECT().GetAadToken(
					gomock.Any(),
					gomock.Any(),
					gomock.Any(),
					gomock.Any(),
					gomock.Any(),
				).Times(0)

				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()

				token, err := tlsBootstrapClient.getAuthToken(ctx, nonEmptyClientID, resource, nil)
				Expect(err).To(BeNil())
				Expect(token).To(Equal("mockMSIToken"))
			})
		})
	})
})
