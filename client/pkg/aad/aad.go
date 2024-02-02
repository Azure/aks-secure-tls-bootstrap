// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package aad

//go:generate ../../../bin/mockgen -copyright_file=../../../hack/copyright_header.txt -destination=./mocks/mock_aad.go -package=mocks github.com/Azure/aks-secure-tls-bootstrap/client/pkg/aad Client

import (
	"context"
	"fmt"
	"strings"

	"github.com/Azure/aks-secure-tls-bootstrap/client/pkg/datamodel"
	"github.com/Azure/aks-secure-tls-bootstrap/client/pkg/util"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/confidential"
	"github.com/hashicorp/go-retryablehttp"
	"go.uber.org/zap"
)

type Client interface {
	GetToken(ctx context.Context, azureConfig *datamodel.AzureConfig, resource string) (string, error)
}

var _ Client = &ClientImpl{}

type ClientImpl struct {
	httpClient *retryablehttp.Client
	logger     *zap.Logger
	fs         util.FS
}

func NewClient(fs util.FS, logger *zap.Logger) *ClientImpl {
	httpClient := retryablehttp.NewClient()
	httpClient.RetryMax = maxGetTokenRetries
	httpClient.RetryWaitMax = maxGetTokenDelay
	return &ClientImpl{
		httpClient: httpClient,
		logger:     logger,
		fs:         fs,
	}
}

func (c *ClientImpl) GetToken(ctx context.Context, azureConfig *datamodel.AzureConfig, resource string) (string, error) {
	scopes := []string{
		fmt.Sprintf("%s/.default", resource),
	}

	credential, err := confidential.NewCredFromSecret(azureConfig.ClientSecret)
	if err != nil {
		return "", fmt.Errorf("failed to create secret credential from azure.json: %w", err)
	}

	authority, err := getAADAuthorityURL(c.fs, azureConfig)
	if err != nil {
		return "", fmt.Errorf("unable to get AAD authority URL: %w", err)
	}

	client, err := confidential.New(authority, azureConfig.ClientID, credential, confidential.WithHTTPClient(c.httpClient.StandardClient()))
	if err != nil {
		return "", fmt.Errorf("failed to create client from azure.json sp/secret: %w", err)
	}

	c.logger.Debug("requesting new AAD token", zap.String("scopes", strings.Join(scopes, ",")), zap.String("authority", authority))
	authResult, err := client.AcquireTokenByCredential(ctx, scopes, confidential.WithTenantID(azureConfig.TenantID))
	if err != nil {
		return "", fmt.Errorf("failed to acquire token via service principal credential: %w", err)
	}
	c.logger.Info("retrierved new AAD token", zap.String("scopes", strings.Join(scopes, ",")), zap.String("authority", authority))

	return authResult.AccessToken, nil
}
