// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package client

//go:generate ../../bin/mockgen -copyright_file=../../hack/copyright_header.txt -destination=./mocks/mock_aad.go -package=mocks github.com/Azure/aks-tls-bootstrap-client/pkg/client AadClient

import (
	"context"
	"fmt"
	"strings"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/confidential"
	"github.com/avast/retry-go/v4"
	"github.com/sirupsen/logrus"
)

type AadClient interface {
	GetAadToken(ctx context.Context, clientID, clientSecret, tenantID, resource string) (string, error)
}

func NewAadClient(logger *logrus.Logger) AadClient {
	return &aadClientImpl{
		Logger:              logger,
		acquireAADTokenFunc: getAADTokenWithCredential,
	}
}

type acquireAADTokenFunc func(ctx context.Context, authority, clientID, clientSecret string, scopes []string) (confidential.AuthResult, error)

type aadClientImpl struct {
	Logger              *logrus.Logger
	acquireAADTokenFunc acquireAADTokenFunc
}

func getAADTokenWithCredential(ctx context.Context, authority, clientID, clientSecret string, scopes []string) (confidential.AuthResult, error) {
	credential, err := confidential.NewCredFromSecret(clientSecret)
	if err != nil {
		return confidential.AuthResult{}, fmt.Errorf("failed to create secret credential from azure.json: %w", err)
	}
	confidentialClient, err := confidential.New(authority, clientID, credential)
	if err != nil {
		return confidential.AuthResult{}, fmt.Errorf("failed to create client from azure.json sp/secret: %w", err)
	}
	result, err := confidentialClient.AcquireTokenByCredential(ctx, scopes)
	if err != nil {
		return confidential.AuthResult{}, fmt.Errorf("unable to acquire token by credential: %w", err)
	}
	return result, nil
}

func (c *aadClientImpl) GetAadToken(ctx context.Context, clientID, clientSecret, tenantID, resource string) (string, error) {
	scopes := []string{
		fmt.Sprintf("%s/.default", resource),
	}

	// TODO(cameissner): modify so this works on all clouds later
	authority := fmt.Sprintf(microsoftLoginAuthorityTemplate, tenantID)

	c.Logger.WithField("scopes", strings.Join(scopes, ",")).Info("requesting new AAD token")

	authResult, err := retry.DoWithData(func() (confidential.AuthResult, error) {
		authResult, err := c.acquireAADTokenFunc(ctx, authority, clientID, clientSecret, scopes)
		if err != nil {
			return confidential.AuthResult{}, fmt.Errorf("unable to acquire AAD token: %w", err)
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
