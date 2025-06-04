// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package bootstrap

import (
	"errors"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"

	"github.com/Azure/aks-secure-tls-bootstrap/client/internal/cloud"
	"github.com/Azure/aks-secure-tls-bootstrap/client/internal/testutil"
	"github.com/Azure/go-autorest/autorest/adal"
	"github.com/Azure/go-autorest/autorest/azure"
)

func TestGetAuthToken(t *testing.T) {
	var (
		logger       *zap.Logger
		testResource = "resource"
		testTenantID = "d87a2c3e-0c0c-42b2-a883-e48cd8723e22"
	)
	logger, _ = zap.NewDevelopment()
	tests := []struct {
		name        string
		customID    string
		setupClient func(*testing.T) *Client
		providerCfg *cloud.ProviderConfig
		expectErr   bool
		errSubstrs  []string
		expectToken string
	}{
		{
			name: "error generating MSI access token",
			setupClient: func(t *testing.T) *Client {
				return &Client{
					logger: logger,
					extractAccessTokenFunc: func(token *adal.ServicePrincipalToken) (string, error) {
						assert.NotNil(t, token)
						return "", errors.New("generating MSI access token")
					},
				}
			},
			providerCfg: &cloud.ProviderConfig{
				UserAssignedIdentityID: "kubelet-identity-id",
				TenantID:               testTenantID,
			},
			expectErr:   true,
			errSubstrs:  []string{"generating MSI access token"},
			expectToken: "",
		},
		{
			name: "error getting azure environment config for specified cloud",
			setupClient: func(t *testing.T) *Client {
				return &Client{
					logger: logger,
					extractAccessTokenFunc: func(token *adal.ServicePrincipalToken) (string, error) {
						return "", nil
					},
				}
			},
			providerCfg: &cloud.ProviderConfig{
				CloudName:    "invalid",
				ClientID:     "service-principal-id",
				ClientSecret: "secret",
				TenantID:     testTenantID,
			},
			expectErr:   true,
			errSubstrs:  []string{`getting azure environment config for cloud "invalid"`},
			expectToken: "",
		},
		{
			name: "service principal client secret contains certificate data",
			setupClient: func(t *testing.T) *Client {
				certData, err := testutil.GenerateCertAndKeyAsEncodedPFXData(testutil.CertTemplate{
					CommonName:   "aad",
					Organization: "azure",
					Expiration:   time.Now().Add(time.Hour),
				})
				assert.NoError(t, err)
				return &Client{
					logger: logger,
					extractAccessTokenFunc: func(token *adal.ServicePrincipalToken) (string, error) {
						assert.NotNil(t, token)
						return "token", nil
					},
					certData: certData,
				}
			},
			providerCfg: &cloud.ProviderConfig{
				CloudName:    azure.PublicCloud.Name,
				ClientID:     "service-principal-id",
				ClientSecret: "certificate:dummy",
				TenantID:     testTenantID,
			},
			expectErr:   false,
			errSubstrs:  nil,
			expectToken: "token",
		},
		// Add the rest of the When/It cases here similarly...
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := tt.setupClient(t)
			token, err := client.getAccessToken(tt.customID, testResource, tt.providerCfg)

			if tt.expectErr {
				assert.Error(t, err)
				for _, substr := range tt.errSubstrs {
					assert.Contains(t, err.Error(), substr)
				}
				assert.Empty(t, token)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectToken, token)
			}
		})
	}
}

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

		When("UserAssignedIdentityID is specified in cloud provider config", func() {
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
