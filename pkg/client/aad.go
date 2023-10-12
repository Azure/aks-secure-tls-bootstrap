// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package client

//go:generate ../../bin/mockgen -copyright_file=../../hack/copyright_header.txt -destination=./mocks/mock_aad.go -package=mocks github.com/Azure/aks-tls-bootstrap-client/pkg/client AadClient,GetTokenInterface

import (
	"context"
	"fmt"
	"strings"

	"github.com/Azure/aks-tls-bootstrap-client/pkg/client/dependencies"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/confidential"
	"github.com/avast/retry-go/v4"
	"github.com/sirupsen/logrus"
)

type AadClient interface {
	GetAadToken(ctx context.Context, clientID, clientSecret, tenantID, resource string) (string, error)
}

func NewAadClient(logger *logrus.Logger) AadClient {
	return &aadClientImpl{
		Logger: logger,
	}
}

type aadClientImpl struct {
	Logger *logrus.Logger
}

// dependency injection for testing GetTokenWithClient
type GetTokenInterface interface {
	GetTokenWithConfidentialClient(ctx context.Context, scopes []string) (string, error)
}
type getTokenWithConfidentialClientImpl struct{}

func NewTokenWithClientInterface() GetTokenInterface {
	return &getTokenWithConfidentialClientImpl{}
}

// global controller that can be overwritten to mock
var getTokenWithConfidentialClientImplFunc = GetTokenInterface(getTokenWithConfidentialClientImpl{})
var aquireTokenClient dependencies.AcquireTokenClient

func (c *aadClientImpl) GetAadToken(ctx context.Context, clientID, clientSecret, tenantID, resource string) (string, error) {
	scopes := []string{
		fmt.Sprintf("%s/.default", resource),
	}

	credential, err := confidential.NewCredFromSecret(clientSecret)
	if err != nil {
		return "", fmt.Errorf("failed to create secret credential from azure.json: %w", err)
	}

	// TODO(cameissner): modify so this works on all clouds later
	authority := fmt.Sprintf(microsoftLoginAuthorityTemplate, tenantID)
	//client, err := confidential.New(authority, clientID, credential)
	aquireTokenClient, err = dependencies.NewTokenClient(authority, clientID, credential)
	if err != nil {
		return "", fmt.Errorf("failed to create client from azure.json sp/secret: %w", err)
	}

	c.Logger.WithField("scopes", strings.Join(scopes, ",")).Info("requesting new AAD token")

	return getTokenWithConfidentialClientImplFunc.GetTokenWithConfidentialClient(ctx, scopes)
}

func (getTokenWithConfidentialClientImpl) GetTokenWithConfidentialClient(ctx context.Context, scopes []string) (string, error) {
	authResult, err := retry.DoWithData(func() (confidential.AuthResult, error) {
		authResult, err := aquireTokenClient.AcquireTokenByCredential(ctx, scopes)
		if err != nil {
			return confidential.AuthResult{}, err
		}
		return authResult, err
	},
		retry.Context(ctx),
		retry.Attempts(getAadTokenMaxRetries),
		retry.MaxDelay(getAadTokenMaxDelay),
		retry.DelayType(retry.BackOffDelay))
	if err != nil {
		return "", fmt.Errorf("failed to acquire token via service principal from AAD: %w", err)
	}
	return authResult.AccessToken, err
}
