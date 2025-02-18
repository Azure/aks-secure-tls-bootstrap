package aad

import (
	"context"
	"fmt"

	"github.com/Azure/aks-secure-tls-bootstrap/client/internal/datamodel"
	internalhttp "github.com/Azure/aks-secure-tls-bootstrap/client/internal/http"
	"github.com/Azure/go-autorest/autorest/azure"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/confidential"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"go.uber.org/zap"
)

var _ = Describe("AAD", Ordered, func() {
	var logger *zap.Logger

	BeforeAll(func() {
		logger, _ = zap.NewDevelopment()
	})

	Context("NewClient", func() {
		It("should construct and return a new client", func() {
			c := NewClient(logger)
			Expect(c).ToNot(BeNil())

			cc, ok := c.(*client)
			Expect(ok).To(BeTrue())
			Expect(cc.logger).ToNot(BeNil())
			Expect(cc.getTokenAcquirer).ToNot(BeNil())
			Expect(cc.httpClient).ToNot(BeNil())
		})
	})

	Context("Client tests", func() {
		var (
			ctx      context.Context
			resource string
			c        *client
		)

		BeforeEach(func() {
			ctx = context.Background()
			resource = "resource"
			c = &client{
				getTokenAcquirer: func(authority, clientID string, cred confidential.Credential, options ...confidential.Option) (tokenAcquirer, error) {
					return &fakeTokenAcquirer{
						AcquireTokenByCredentialFunc: func(ctx context.Context, scopes []string, opts ...confidential.AcquireByCredentialOption) (confidential.AuthResult, error) {
							return confidential.AuthResult{}, nil
						},
					}, nil
				},
				httpClient: internalhttp.NewClient(logger),
				logger:     logger,
			}
		})

		When("unable to create new credential from secret", func() {
			It("should return an error", func() {
				azureConfig := &datamodel.AzureConfig{
					ClientID:     "clientId",
					ClientSecret: "",
				}

				token, err := c.GetToken(ctx, azureConfig, resource)
				Expect(token).To(BeEmpty())
				Expect(err).ToNot(BeNil())
				Expect(err.Error()).To(ContainSubstring("creating credential from client secret"))
			})
		})

		When("cloud environment name is invalid", func() {
			It("should return an error", func() {
				azureConfig := &datamodel.AzureConfig{
					ClientID:     "clientId",
					ClientSecret: "clientSecret",
					Cloud:        "invalid",
				}

				token, err := c.GetToken(ctx, azureConfig, resource)
				Expect(token).To(BeEmpty())
				Expect(err).ToNot(BeNil())
				Expect(err.Error()).To(ContainSubstring(`getting azure environment from cloud name "invalid"`))
			})
		})

		When("unable to create a new token acquirer", func() {
			It("should return an error", func() {
				c.getTokenAcquirer = func(authority, clientID string, cred confidential.Credential, options ...confidential.Option) (tokenAcquirer, error) {
					return nil, fmt.Errorf("unable to create a new token acquirer")
				}
				azureConfig := &datamodel.AzureConfig{
					ClientID:     "clientId",
					ClientSecret: "clientSecret",
					Cloud:        azure.PublicCloud.Name,
				}

				token, err := c.GetToken(ctx, azureConfig, resource)
				Expect(token).To(BeEmpty())
				Expect(err).ToNot(BeNil())
				Expect(err.Error()).To(ContainSubstring("creating confidential client with secret credential: unable to create a new token acquirer"))
			})
		})

		When("unable to acquire a token", func() {
			It("should return an error", func() {
				c.getTokenAcquirer = func(authority, clientID string, cred confidential.Credential, options ...confidential.Option) (tokenAcquirer, error) {
					return &fakeTokenAcquirer{
						AcquireTokenByCredentialFunc: func(ctx context.Context, scopes []string, opts ...confidential.AcquireByCredentialOption) (confidential.AuthResult, error) {
							return confidential.AuthResult{}, fmt.Errorf("unable to acquire a token")
						},
					}, nil
				}
				azureConfig := &datamodel.AzureConfig{
					ClientID:     "clientId",
					ClientSecret: "clientSecret",
					Cloud:        azure.PublicCloud.Name,
				}

				token, err := c.GetToken(ctx, azureConfig, resource)
				Expect(token).To(BeEmpty())
				Expect(err).ToNot(BeNil())
				Expect(err.Error()).To(ContainSubstring("acquiring AAD token with secret credential: unable to acquire a token"))
			})
		})

		When("a new token can be acquired", func() {
			It("should return the token without error", func() {
				result := confidential.AuthResult{
					AccessToken: "token",
				}
				c.getTokenAcquirer = func(authority, clientID string, cred confidential.Credential, options ...confidential.Option) (tokenAcquirer, error) {
					return &fakeTokenAcquirer{
						AcquireTokenByCredentialFunc: func(ctx context.Context, scopes []string, opts ...confidential.AcquireByCredentialOption) (confidential.AuthResult, error) {
							return result, nil
						},
					}, nil
				}
				azureConfig := &datamodel.AzureConfig{
					ClientID:     "clientId",
					ClientSecret: "clientSecret",
					Cloud:        azure.PublicCloud.Name,
				}

				token, err := c.GetToken(ctx, azureConfig, resource)
				Expect(err).To(BeNil())
				Expect(token).To(Equal(result.AccessToken))
			})
		})
	})
})
