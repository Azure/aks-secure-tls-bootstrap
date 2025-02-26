// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package bootstrap

import (
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"go.uber.org/zap"

	"github.com/Azure/aks-secure-tls-bootstrap/client/internal/datamodel"
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
			getMSITokenFunc: func(resource string, options *adal.ManagedIdentityOptions, callbacks ...adal.TokenRefreshCallback) (*adal.ServicePrincipalToken, error) {
				return nil, nil
			},
			getServicePrincipalTokenFunc: func(oauthConfig adal.OAuthConfig, clientID, secret, resource string, callbacks ...adal.TokenRefreshCallback) (*adal.ServicePrincipalToken, error) {
				return nil, nil
			},
			getServicePrincipalTokenWithCertFunc: func(oauthConfig adal.OAuthConfig, clientID string, certificate *x509.Certificate, privateKey *rsa.PrivateKey, resource string, callbacks ...adal.TokenRefreshCallback) (*adal.ServicePrincipalToken, error) {
				return nil, nil
			},
			extractAccessTokenFunc: func(servicePrincipalToken *adal.ServicePrincipalToken) string {
				Expect(servicePrincipalToken).ToNot(BeNil())
				return "token"
			},
		}
	})

	Context("getAuthToken", func() {
		var testResource = "resource"
		var testTenantID = "d87a2c3e-0c0c-42b2-a883-e48cd8723e22"

		When("there is an error generating an MSI access token", func() {
			It("should return an error", func() {
				azureConfig := &datamodel.AzureConfig{
					UserAssignedIdentityID: "kubelet-identity-id",
					TenantID:               testTenantID,
				}
				bootstrapClient.getMSITokenFunc = func(resource string, options *adal.ManagedIdentityOptions, callbacks ...adal.TokenRefreshCallback) (*adal.ServicePrincipalToken, error) {
					Expect(testResource).To(Equal(resource))
					Expect(options).ToNot(BeNil())
					Expect(options.ClientID).To(Equal(azureConfig.UserAssignedIdentityID))
					return nil, fmt.Errorf("cannot generate MSI token")
				}

				token, err := bootstrapClient.getAuthToken("", testResource, azureConfig)
				Expect(token).To(BeEmpty())
				Expect(err).To(MatchError("generating MSI access token: cannot generate MSI token"))
			})
		})

		When("there is an error getting the azure environment config for the specified cloud", func() {
			It("should return an error", func() {
				azureConfig := &datamodel.AzureConfig{
					Cloud:        "invalid",
					ClientID:     "service-principal-id",
					ClientSecret: "secret",
					TenantID:     testTenantID,
				}

				token, err := bootstrapClient.getAuthToken("", testResource, azureConfig)
				Expect(token).To(BeEmpty())
				Expect(err).To(MatchError(ContainSubstring(`getting azure environment config for cloud "invalid"`)))
			})
		})

		When("there is an error generating a service principal access token with username and password", func() {
			It("should return an error", func() {
				azureConfig := &datamodel.AzureConfig{
					Cloud:        azure.PublicCloud.Name,
					ClientID:     "service-principal-id",
					ClientSecret: "secret",
					TenantID:     testTenantID,
				}
				bootstrapClient.getServicePrincipalTokenFunc = func(oauthConfig adal.OAuthConfig, clientID, secret, resource string, callbacks ...adal.TokenRefreshCallback) (*adal.ServicePrincipalToken, error) {
					Expect(oauthConfig).ToNot(BeNil())
					Expect(clientID).To(Equal(azureConfig.ClientID))
					Expect(secret).To(Equal(azureConfig.ClientSecret))
					Expect(resource).To(Equal(testResource))
					return nil, fmt.Errorf("cannot generate SPN token with username and password")
				}

				token, err := bootstrapClient.getAuthToken("", testResource, azureConfig)
				Expect(token).To(BeEmpty())
				Expect(err).To(MatchError("generating SPN access token with username and password: cannot generate SPN token with username and password"))
			})
		})

		When("there is an error b64-decoding the certificate data", func() {
			It("should return an error", func() {
				azureConfig := &datamodel.AzureConfig{
					Cloud:        azure.PublicCloud.Name,
					ClientID:     "service-principal-id",
					ClientSecret: "certificate:YW55IGNhcm5hbCBwbGVhc3U======", // invalid b64-encoding
					TenantID:     testTenantID,
				}

				token, err := bootstrapClient.getAuthToken("", testResource, azureConfig)
				Expect(token).To(BeEmpty())
				Expect(err).To(MatchError(ContainSubstring("b64-decoding certificate data in client secret")))
			})
		})

		When("there is an error decoding the pfx certificate data", func() {
			It("should return an error", func() {
				azureConfig := &datamodel.AzureConfig{
					Cloud:        azure.PublicCloud.Name,
					ClientID:     "service-principal-id",
					ClientSecret: "certificate:dGVzdAo=", // b64-encoding of "test"
					TenantID:     testTenantID,
				}

				token, err := bootstrapClient.getAuthToken("", testResource, azureConfig)
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

				azureConfig := &datamodel.AzureConfig{
					Cloud:        azure.PublicCloud.Name,
					ClientID:     "service-principal-id",
					ClientSecret: "certificate:" + certData,
					TenantID:     testTenantID,
				}
				bootstrapClient.getServicePrincipalTokenWithCertFunc = func(oauthConfig adal.OAuthConfig, clientID string, certificate *x509.Certificate, privateKey *rsa.PrivateKey, resource string, callbacks ...adal.TokenRefreshCallback) (*adal.ServicePrincipalToken, error) {
					Expect(oauthConfig).ToNot(BeNil())
					Expect(clientID).To(Equal(azureConfig.ClientID))
					Expect(certificate).ToNot(BeNil())
					Expect(privateKey).ToNot(BeNil())
					Expect(resource).To(Equal(testResource))
					return nil, fmt.Errorf("cannot generate SPN token with cert data")
				}

				token, err := bootstrapClient.getAuthToken("", testResource, azureConfig)
				Expect(token).To(BeEmpty())
				Expect(err).To(MatchError("generating SPN access token with certificate: cannot generate SPN token with cert data"))
			})
		})

		When("UserAssignedIdentityID is specified in azure config", func() {
			It("should return a corresponding MSI access token", func() {
				azureConfig := &datamodel.AzureConfig{
					UserAssignedIdentityID: "kubelet-identity-id",
					TenantID:               testTenantID,
				}
				bootstrapClient.getMSITokenFunc = func(resource string, options *adal.ManagedIdentityOptions, callbacks ...adal.TokenRefreshCallback) (*adal.ServicePrincipalToken, error) {
					Expect(testResource).To(Equal(resource))
					Expect(options).ToNot(BeNil())
					Expect(options.ClientID).To(Equal(azureConfig.UserAssignedIdentityID))
					return &adal.ServicePrincipalToken{}, nil
				}
				bootstrapClient.getServicePrincipalTokenFunc = func(oauthConfig adal.OAuthConfig, clientID, secret, resource string, callbacks ...adal.TokenRefreshCallback) (*adal.ServicePrincipalToken, error) {
					Expect(false).To(BeTrue(), "getServicePrincipalToken should not have been called")
					return nil, nil
				}
				bootstrapClient.getServicePrincipalTokenWithCertFunc = func(oauthConfig adal.OAuthConfig, clientID string, certificate *x509.Certificate, privateKey *rsa.PrivateKey, resource string, callbacks ...adal.TokenRefreshCallback) (*adal.ServicePrincipalToken, error) {
					Expect(false).To(BeTrue(), "getServicePrincipalTokenWithCert should not have been called")
					return nil, nil
				}

				token, err := bootstrapClient.getAuthToken("", testResource, azureConfig)
				Expect(err).To(BeNil())
				Expect(token).To(Equal("token"))
			})
		})

		When("a custom client ID is specified", func() {
			It("should return a corresponding MSI access token from IMDS", func() {
				customClientID := "custom"
				azureConfig := &datamodel.AzureConfig{
					UserAssignedIdentityID: "kubelet-identity-id",
					TenantID:               testTenantID,
				}
				bootstrapClient.getMSITokenFunc = func(resource string, options *adal.ManagedIdentityOptions, callbacks ...adal.TokenRefreshCallback) (*adal.ServicePrincipalToken, error) {
					Expect(testResource).To(Equal(resource))
					Expect(options).ToNot(BeNil())
					Expect(options.ClientID).To(Equal(customClientID))
					return &adal.ServicePrincipalToken{}, nil
				}
				bootstrapClient.getServicePrincipalTokenFunc = func(oauthConfig adal.OAuthConfig, clientID, secret, resource string, callbacks ...adal.TokenRefreshCallback) (*adal.ServicePrincipalToken, error) {
					Expect(false).To(BeTrue(), "getServicePrincipalToken should not have been called")
					return nil, nil
				}
				bootstrapClient.getServicePrincipalTokenWithCertFunc = func(oauthConfig adal.OAuthConfig, clientID string, certificate *x509.Certificate, privateKey *rsa.PrivateKey, resource string, callbacks ...adal.TokenRefreshCallback) (*adal.ServicePrincipalToken, error) {
					Expect(false).To(BeTrue(), "getServicePrincipalTokenWithCert should not have been called")
					return nil, nil
				}

				token, err := bootstrapClient.getAuthToken(customClientID, testResource, azureConfig)
				Expect(err).To(BeNil())
				Expect(token).To(Equal("token"))
			})
		})

		When("service principal client secret does not contain certificate data", func() {
			It("should return a corresponding SPN access token using username + password auth", func() {
				azureConfig := &datamodel.AzureConfig{
					Cloud:        azure.PublicCloud.Name,
					ClientID:     "service-principal-id",
					ClientSecret: "secret",
					TenantID:     testTenantID,
				}
				bootstrapClient.getMSITokenFunc = func(resource string, options *adal.ManagedIdentityOptions, callbacks ...adal.TokenRefreshCallback) (*adal.ServicePrincipalToken, error) {
					Expect(false).To(BeTrue(), "getMSIToken should not have been called")
					return nil, nil
				}
				bootstrapClient.getServicePrincipalTokenFunc = func(oauthConfig adal.OAuthConfig, clientID, secret, resource string, callbacks ...adal.TokenRefreshCallback) (*adal.ServicePrincipalToken, error) {
					Expect(oauthConfig).ToNot(BeNil())
					Expect(clientID).To(Equal(azureConfig.ClientID))
					Expect(secret).To(Equal(azureConfig.ClientSecret))
					Expect(resource).To(Equal(testResource))
					return &adal.ServicePrincipalToken{}, nil
				}
				bootstrapClient.getServicePrincipalTokenWithCertFunc = func(oauthConfig adal.OAuthConfig, clientID string, certificate *x509.Certificate, privateKey *rsa.PrivateKey, resource string, callbacks ...adal.TokenRefreshCallback) (*adal.ServicePrincipalToken, error) {
					Expect(false).To(BeTrue(), "getServicePrincipalTokenWithCert should not have been called")
					return nil, nil
				}

				token, err := bootstrapClient.getAuthToken("", testResource, azureConfig)
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

				azureConfig := &datamodel.AzureConfig{
					Cloud:        azure.PublicCloud.Name,
					ClientID:     "service-principal-id",
					ClientSecret: "certificate:" + certData,
					TenantID:     testTenantID,
				}
				bootstrapClient.getMSITokenFunc = func(resource string, options *adal.ManagedIdentityOptions, callbacks ...adal.TokenRefreshCallback) (*adal.ServicePrincipalToken, error) {
					Expect(false).To(BeTrue(), "getMSIToken should not have been called")
					return nil, nil
				}
				bootstrapClient.getServicePrincipalTokenFunc = func(oauthConfig adal.OAuthConfig, clientID, secret, resource string, callbacks ...adal.TokenRefreshCallback) (*adal.ServicePrincipalToken, error) {
					Expect(false).To(BeTrue(), "getServicePrincipalToken should not have been called")
					return nil, nil
				}
				bootstrapClient.getServicePrincipalTokenWithCertFunc = func(oauthConfig adal.OAuthConfig, clientID string, certificate *x509.Certificate, privateKey *rsa.PrivateKey, resource string, callbacks ...adal.TokenRefreshCallback) (*adal.ServicePrincipalToken, error) {
					Expect(oauthConfig).ToNot(BeNil())
					Expect(clientID).To(Equal(azureConfig.ClientID))
					Expect(certificate).ToNot(BeNil())
					Expect(privateKey).ToNot(BeNil())
					Expect(resource).To(Equal(testResource))
					return &adal.ServicePrincipalToken{}, nil
				}

				token, err := bootstrapClient.getAuthToken("", testResource, azureConfig)
				Expect(err).To(BeNil())
				Expect(token).To(Equal("token"))
			})
		})

	})
})
