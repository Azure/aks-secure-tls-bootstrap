// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package client

import (
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
		When("clientId is not supplied", func() {
			var emptyClientID = ""

			When("azure json is missing clientId", func() {
				It("should return an error", func() {
					imdsClient.EXPECT().GetMSIToken(gomock.Any(), gomock.Any()).Times(0)
					aadClient.EXPECT().GetAadToken(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Times(0)
					azureConfig := &datamodel.KubeletAzureJSON{
						ClientSecret: "secret",
						TenantID:     "tid",
					}

					spToken, err := tlsBootstrapClient.getAuthToken(emptyClientID, azureConfig)
					Expect(spToken).To(BeEmpty())
					Expect(err).ToNot(BeNil())
					Expect(err.Error()).To(ContainSubstring("cannot retrieve SP token from AAD: azure.json missing clientId"))
				})
			})

			When("azure json is missing clientSecret", func() {
				It("should return an error", func() {
					imdsClient.EXPECT().GetMSIToken(gomock.Any(), gomock.Any()).Times(0)
					aadClient.EXPECT().GetAadToken(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Times(0)
					azureConfig := &datamodel.KubeletAzureJSON{
						ClientID: "cid",
						TenantID: "tid",
					}

					spToken, err := tlsBootstrapClient.getAuthToken(emptyClientID, azureConfig)
					Expect(spToken).To(BeEmpty())
					Expect(err).ToNot(BeNil())
					Expect(err.Error()).To(ContainSubstring("cannot retrieve SP token from AAD: azure.json missing clientSecret"))
				})
			})

			When("azure json is missing tenantId", func() {
				It("should return an error", func() {
					imdsClient.EXPECT().GetMSIToken(gomock.Any(), gomock.Any()).Times(0)
					aadClient.EXPECT().GetAadToken(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Times(0)
					azureConfig := &datamodel.KubeletAzureJSON{
						ClientID:     "cid",
						ClientSecret: "secret",
					}

					spToken, err := tlsBootstrapClient.getAuthToken(emptyClientID, azureConfig)
					Expect(spToken).To(BeEmpty())
					Expect(err).ToNot(BeNil())
					Expect(err.Error()).To(ContainSubstring("cannot retrieve SP token from AAD: azure.json missing tenantId"))
				})
			})

			When("azure json contains msi clientId and userAssignedIdentityId is non-empty", func() {
				It("should acquire MSI token from IMDS using userAssignedIdentityId as clientId", func() {
					userAssignedIdentityID := "uami"
					imdsClient.EXPECT().GetMSIToken(baseImdsURL, userAssignedIdentityID).Return(
						&datamodel.TokenResponseJSON{
							AccessToken: "mockMSIToken",
						}, nil,
					).Times(1)
					aadClient.EXPECT().GetAadToken(
						gomock.Any(),
						gomock.Any(),
						gomock.Any(),
						gomock.Any(),
					).Times(0)
					azureConfigMsi := &datamodel.KubeletAzureJSON{
						ClientID:               "msi",
						UserAssignedIdentityID: userAssignedIdentityID,
					}

					msiToken, err := tlsBootstrapClient.getAuthToken(emptyClientID, azureConfigMsi)
					Expect(err).To(BeNil())
					Expect(msiToken).To(Equal("mockMSIToken"))
				})
			})

			When("azure json contains msi clientId and userAssignedIdentityId is empty", func() {
				It("should acquire MSI token from IMDS", func() {
					imdsClient.EXPECT().GetMSIToken(baseImdsURL, emptyClientID).Return(
						&datamodel.TokenResponseJSON{
							AccessToken: "mockMSIToken",
						}, nil,
					).Times(1)
					aadClient.EXPECT().GetAadToken(
						gomock.Any(),
						gomock.Any(),
						gomock.Any(),
						gomock.Any(),
					).Times(0)
					azureConfigMsi := &datamodel.KubeletAzureJSON{
						ClientID: "msi",
					}

					msiToken, err := tlsBootstrapClient.getAuthToken(emptyClientID, azureConfigMsi)
					Expect(err).To(BeNil())
					Expect(msiToken).To(Equal("mockMSIToken"))
				})
			})

			When("azure json contains non-MSI clientId", func() {
				It("should use service principal and acquire token from AAD", func() {
					aadClient.EXPECT().GetAadToken("no-msi", "secret", "tenantId", gomock.Any()).Return(
						"spToken",
						nil,
					).Times(1)
					imdsClient.EXPECT().GetMSIToken(
						gomock.Any(), gomock.Any(),
					).Times(0)
					azureConfigNoMsi := &datamodel.KubeletAzureJSON{
						ClientID:     "no-msi",
						ClientSecret: "secret",
						TenantID:     "tenantId",
					}

					spToken, err := tlsBootstrapClient.getAuthToken(emptyClientID, azureConfigNoMsi)
					Expect(err).To(BeNil())
					Expect(spToken).To(Equal("spToken"))
				})
			})
		})

		When("clientId is supplied", func() {
			var nonEmptyClientID = "clientId"

			It("should acquire MSI token from IMDS", func() {
				imdsClient.EXPECT().GetMSIToken(baseImdsURL, nonEmptyClientID).Return(
					&datamodel.TokenResponseJSON{
						AccessToken: "mockMSIToken",
					}, nil,
				).Times(1)
				aadClient.EXPECT().GetAadToken(
					gomock.Any(),
					gomock.Any(),
					gomock.Any(),
					gomock.Any(),
				).Times(0)

				token, err := tlsBootstrapClient.getAuthToken(nonEmptyClientID, nil)
				Expect(err).To(BeNil())
				Expect(token).To(Equal("mockMSIToken"))
			})
		})
	})
})
