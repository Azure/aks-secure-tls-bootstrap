// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package bootstrap

import (
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"go.uber.org/zap"

	"github.com/Azure/aks-secure-tls-bootstrap/client/internal/cloud"
	"github.com/Azure/aks-secure-tls-bootstrap/client/internal/testutil"
	"github.com/Azure/go-autorest/autorest/adal"
	"github.com/Azure/go-autorest/autorest/azure"
)

var _ = Describe("Auth", Ordered, func() {
	var (
		logger          *zap.Logger
		bootstrapClient *Client
	)

	BeforeAll(func() {
		logger, _ = zap.NewDevelopment()
	})

	BeforeEach(func() {
		bootstrapClient = &Client{
			logger: logger,
			extractAccessTokenFunc: func(token *adal.ServicePrincipalToken) (string, error) {
				Expect(token).ToNot(BeNil())
				return "token", nil
			},
		}
	})

	Context("getAuthToken", func() {
		var testResource = "resource"
		var testTenantID = "d87a2c3e-0c0c-42b2-a883-e48cd8723e22"

		When("there is an error generating an MSI access token", func() {
			It("should return an error", func() {
				cloudProviderConfig := &cloud.ProviderConfig{
					UserAssignedIdentityID: "kubelet-identity-id",
					TenantID:               testTenantID,
				}

				token, err := bootstrapClient.getAccessToken("", "", cloudProviderConfig) // pass an empty resource to force a failure
				Expect(token).To(BeEmpty())
				Expect(err).To(MatchError(ContainSubstring("generating MSI access token")))
			})
		})

		When("there is an error getting the azure environment config for the specified cloud", func() {
			It("should return an error", func() {
				cloudProviderConfig := &cloud.ProviderConfig{
					CloudName:    "invalid",
					ClientID:     "service-principal-id",
					ClientSecret: "secret",
					TenantID:     testTenantID,
				}

				token, err := bootstrapClient.getAccessToken("", testResource, cloudProviderConfig)
				Expect(token).To(BeEmpty())
				Expect(err).To(MatchError(ContainSubstring(`getting azure environment config for cloud "invalid"`)))
			})
		})

		When("there is an error generating a service principal access token with username and password", func() {
			It("should return an error", func() {
				cloudProviderConfig := &cloud.ProviderConfig{
					CloudName:    azure.PublicCloud.Name,
					ClientID:     "service-principal-id",
					ClientSecret: "", // empty secret to force a failure
					TenantID:     testTenantID,
				}

				token, err := bootstrapClient.getAccessToken("", testResource, cloudProviderConfig)
				Expect(token).To(BeEmpty())
				Expect(err).To(MatchError(ContainSubstring("generating SPN access token with username and password")))
			})
		})

		When("there is an error b64-decoding the certificate data", func() {
			It("should return an error", func() {
				cloudProviderConfig := &cloud.ProviderConfig{
					CloudName:    azure.PublicCloud.Name,
					ClientID:     "service-principal-id",
					ClientSecret: "certificate:YW55IGNhcm5hbCBwbGVhc3U======", // invalid b64-encoding
					TenantID:     testTenantID,
				}

				token, err := bootstrapClient.getAccessToken("", testResource, cloudProviderConfig)
				Expect(token).To(BeEmpty())
				Expect(err).To(MatchError(ContainSubstring("b64-decoding certificate data in client secret")))
			})
		})

		When("there is an error decoding the pfx certificate data", func() {
			It("should return an error", func() {
				cloudProviderConfig := &cloud.ProviderConfig{
					CloudName:    azure.PublicCloud.Name,
					ClientID:     "service-principal-id",
					ClientSecret: "certificate:dGVzdAo=", // b64-encoding of "test"
					TenantID:     testTenantID,
				}

				token, err := bootstrapClient.getAccessToken("", testResource, cloudProviderConfig)
				Expect(token).To(BeEmpty())
				Expect(err).To(MatchError(ContainSubstring("decoding pfx certificate data in client secret")))
			})
		})

		When("there is an error generating a service principal token with certificate data", func() {
			It("should return an error", func() {
				certData, err := testutil.GenerateCertAndKeyAsEncodedPFXData(testutil.CertTemplate{
					CommonName:   "aad",
					Organization: "azure",
					Expiration:   time.Now().Add(time.Hour),
				})
				Expect(err).To(BeNil())

				cloudProviderConfig := &cloud.ProviderConfig{
					CloudName:    azure.PublicCloud.Name,
					ClientID:     "service-principal-id",
					ClientSecret: "certificate:" + certData,
					TenantID:     testTenantID,
				}

				token, err := bootstrapClient.getAccessToken("", "", cloudProviderConfig) // pass an empty resource to force a failure
				Expect(token).To(BeEmpty())
				Expect(err).To(MatchError(ContainSubstring("generating SPN access token with certificate")))
			})
		})

		When("UserAssignedIdentityID is specified in azure config", func() {
			It("should return a corresponding MSI access token", func() {
				cloudProviderConfig := &cloud.ProviderConfig{
					UserAssignedIdentityID: "kubelet-identity-id",
					TenantID:               testTenantID,
				}

				token, err := bootstrapClient.getAccessToken("", testResource, cloudProviderConfig)
				Expect(err).To(BeNil())
				Expect(token).To(Equal("token"))
			})
		})

		When("a custom client ID is specified", func() {
			It("should return a corresponding MSI access token from IMDS", func() {
				customClientID := "custom"
				cloudProviderConfig := &cloud.ProviderConfig{
					UserAssignedIdentityID: "kubelet-identity-id",
					TenantID:               testTenantID,
				}

				token, err := bootstrapClient.getAccessToken(customClientID, testResource, cloudProviderConfig)
				Expect(err).To(BeNil())
				Expect(token).To(Equal("token"))
			})
		})

		When("service principal client secret does not contain certificate data", func() {
			It("should return a corresponding SPN access token using username + password auth", func() {
				cloudProviderConfig := &cloud.ProviderConfig{
					CloudName:    azure.PublicCloud.Name,
					ClientID:     "service-principal-id",
					ClientSecret: "secret",
					TenantID:     testTenantID,
				}

				token, err := bootstrapClient.getAccessToken("", testResource, cloudProviderConfig)
				Expect(err).To(BeNil())
				Expect(token).To(Equal("token"))
			})
		})

		When("service principal client secret contains certificate data", func() {
			It("should return a corresponding SPN access token using certificate auth", func() {
				certData, err := testutil.GenerateCertAndKeyAsEncodedPFXData(testutil.CertTemplate{
					CommonName:   "aad",
					Organization: "azure",
					Expiration:   time.Now().Add(time.Hour),
				})
				Expect(err).To(BeNil())

				cloudProviderConfig := &cloud.ProviderConfig{
					CloudName:    azure.PublicCloud.Name,
					ClientID:     "service-principal-id",
					ClientSecret: "certificate:" + certData,
					TenantID:     testTenantID,
				}

				token, err := bootstrapClient.getAccessToken("", testResource, cloudProviderConfig)
				Expect(err).To(BeNil())
				Expect(token).To(Equal("token"))
			})
		})

	})
})
