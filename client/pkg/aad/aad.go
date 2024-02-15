// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package aad

//go:generate ../../../bin/mockgen -copyright_file=../../../hack/copyright_header.txt -destination=./mocks/mock_aad.go -package=mocks github.com/Azure/aks-secure-tls-bootstrap/client/pkg/aad Client

import (
	"context"
	"fmt"

	"github.com/Azure/aks-secure-tls-bootstrap/client/pkg/datamodel"
	"github.com/Azure/go-autorest/autorest/azure"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/confidential"
	"github.com/hashicorp/go-retryablehttp"
	"go.uber.org/zap"
)

type Client interface {
	GetToken(ctx context.Context, azureConfig *datamodel.AzureConfig, resource string) (string, error)
}

var _ Client = (*ClientImpl)(nil)

type ClientImpl struct {
	httpClient *retryablehttp.Client
	logger     *zap.Logger
}

func NewClient(logger *zap.Logger) *ClientImpl {
	httpClient := retryablehttp.NewClient()
	httpClient.RetryMax = maxGetTokenRetries
	httpClient.RetryWaitMax = maxGetTokenDelay
	return &ClientImpl{
		httpClient: httpClient,
		logger:     logger,
	}
}

func (c *ClientImpl) GetToken(ctx context.Context, azureConfig *datamodel.AzureConfig, resource string) (string, error) {
	scopes := []string{
		fmt.Sprintf("%s/.default", resource),
	}

	credential, err := confidential.NewCredFromSecret(azureConfig.ClientSecret)
	if err != nil {
		return "", fmt.Errorf("failed to create confidential secret credential from azure.json: %w", err)
	}

	// confirmed that this value will be AzureStackCloud in AGC environments
	env, err := azure.EnvironmentFromName(azureConfig.Cloud)
	if err != nil {
		return "", fmt.Errorf("getting azure environment from name %q: %w", azureConfig.Cloud, err)
	}

	client, err := confidential.New(
		env.ActiveDirectoryEndpoint,
		azureConfig.ClientID,
		credential,
		confidential.WithHTTPClient(c.httpClient.StandardClient()))
	if err != nil {
		return "", fmt.Errorf("failed to create confidential client from azure.json sp/secret: %w", err)
	}

	logger := c.logger.With(
		zap.Strings("scopes", scopes),
		zap.String("aadEndpoint", env.ActiveDirectoryEndpoint),
		zap.String("clientID", azureConfig.ClientID),
		zap.String("tenantID", azureConfig.TenantID))
	logger.Debug("requesting new AAD token")
	authResult, err := client.AcquireTokenByCredential(ctx, scopes, confidential.WithTenantID(azureConfig.TenantID))
	if err != nil {
		return "", fmt.Errorf("failed to acquire token via service principal credential: %w", err)
	}
	logger.Info("retrieved new AAD token")

	return authResult.AccessToken, nil
}
