// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package aad

//go:generate ../../bin/mockgen -copyright_file=../../../hack/copyright_header.txt -destination=./mocks/mock_aad.go -package=mocks github.com/Azure/aks-secure-tls-bootstrap/client/pkg/aad Client

import (
	"context"
	"fmt"

	"github.com/Azure/aks-secure-tls-bootstrap/client/pkg/datamodel"
	"github.com/Azure/aks-secure-tls-bootstrap/client/pkg/http"
	"github.com/Azure/go-autorest/autorest/azure"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/confidential"
	"go.uber.org/zap"
)

// tokenAcquirer provides an interface for acquiring AAD tokens via a credential. Fake implementations provided in unit tests.
type tokenAcquirer interface {
	AcquireTokenByCredential(ctx context.Context, scopes []string, opts ...confidential.AcquireByCredentialOption) (confidential.AuthResult, error)
}

// getTokenAcquirerFunc returns a tokenAcquirer based on the specified parameters. Fake implementations provided in unit tests.
type getTokenAcquirerFunc func(authority string, clientID string, cred confidential.Credential, options ...confidential.Option) (tokenAcquirer, error)

// getConfidentialAcquirer returns a tokenAcquirer implementation backed by a confidential client.
func getConfidentialAcquirer(authority string, clientID string, cred confidential.Credential, options ...confidential.Option) (tokenAcquirer, error) {
	return confidential.New(authority, clientID, cred, options...)
}

type Client interface {
	GetToken(ctx context.Context, azureConfig *datamodel.AzureConfig, resource string) (string, error)
}

var _ Client = (*client)(nil)

type client struct {
	getTokenAcquirer getTokenAcquirerFunc
	httpClient       *http.Client
	logger           *zap.Logger
}

func NewClient(logger *zap.Logger) Client {
	return &client{
		getTokenAcquirer: getConfidentialAcquirer,
		httpClient:       http.NewClient(http.WithRetryMax(maxGetTokenRetries), http.WithRetryWaitMax(maxGetTokenDelay)),
		logger:           logger,
	}
}

func (c *client) GetToken(ctx context.Context, azureConfig *datamodel.AzureConfig, resource string) (string, error) {
	scopes := []string{
		fmt.Sprintf("%s/.default", resource),
	}

	credential, err := confidential.NewCredFromSecret(azureConfig.ClientSecret)
	if err != nil {
		return "", fmt.Errorf("creating credential from client secret: %w", err)
	}

	env, err := azure.EnvironmentFromName(azureConfig.Cloud)
	if err != nil {
		return "", fmt.Errorf("getting azure environment from cloud name %q: %w", azureConfig.Cloud, err)
	}

	acquirer, err := c.getTokenAcquirer(
		env.ActiveDirectoryEndpoint,
		azureConfig.ClientID,
		credential,
		confidential.WithHTTPClient(c.httpClient.StandardClient()))
	if err != nil {
		return "", fmt.Errorf("creating confidential client with secret credential: %w", err)
	}

	result, err := acquirer.AcquireTokenByCredential(ctx, scopes, confidential.WithTenantID(azureConfig.TenantID))
	if err != nil {
		return "", fmt.Errorf("acquiring AAD token with secret credential: %w", err)
	}
	c.logger.Info("retrieved new AAD token",
		zap.Strings("scopes", scopes),
		zap.String("aadEndpoint", env.ActiveDirectoryEndpoint),
		zap.String("clientID", azureConfig.ClientID),
		zap.String("tenantID", azureConfig.TenantID),
	)

	return result.AccessToken, nil
}
