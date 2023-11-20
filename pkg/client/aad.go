// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package client

//go:generate ../../bin/mockgen -copyright_file=../../hack/copyright_header.txt -destination=./mocks/mock_aad.go -package=mocks github.com/Azure/aks-tls-bootstrap-client/pkg/client AadClient

import (
	"context"
	"fmt"
	"strings"

	"github.com/Azure/aks-tls-bootstrap-client/pkg/datamodel"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/confidential"
	"github.com/avast/retry-go/v4"
	"go.uber.org/zap"
)

type AadClient interface {
	GetAadToken(ctx context.Context, azureConfig *datamodel.AzureConfig, resource string) (string, error)
}

func NewAadClient(reader fileReader, logger *zap.Logger) AadClient {
	return &aadClientImpl{
		reader: reader,
		logger: logger,
	}
}

type aadClientImpl struct {
	reader fileReader
	logger *zap.Logger
}

func (c *aadClientImpl) GetAadToken(ctx context.Context, azureConfig *datamodel.AzureConfig, resource string) (string, error) {
	scopes := []string{
		fmt.Sprintf("%s/.default", resource),
	}

	credential, err := confidential.NewCredFromSecret(azureConfig.ClientSecret)
	if err != nil {
		return "", fmt.Errorf("failed to create secret credential from azure.json: %w", err)
	}

	authority, err := getAADAuthorityURL(c.reader, azureConfig)
	if err != nil {
		return "", fmt.Errorf("unable to get AAD authority URL: %w", err)
	}

	client, err := confidential.New(authority, azureConfig.ClientID, credential)
	if err != nil {
		return "", fmt.Errorf("failed to create client from azure.json sp/secret: %w", err)
	}

	c.logger.Info("requesting new AAD token", zap.String("scopes", strings.Join(scopes, ",")))

	authResult, err := retry.DoWithData(func() (confidential.AuthResult, error) {
		authResult, err := client.AcquireTokenByCredential(ctx, scopes)
		if err != nil {
			return confidential.AuthResult{}, err
		}
		return authResult, nil
	},
		retry.Context(ctx),
		retry.Attempts(getAadTokenMaxRetries),
		retry.MaxDelay(getAadTokenMaxDelay),
		retry.DelayType(retry.BackOffDelay))
	if err != nil {
		return "", fmt.Errorf("failed to acquire token via service principal from AAD: %w", err)
	}

	return authResult.AccessToken, nil
}
