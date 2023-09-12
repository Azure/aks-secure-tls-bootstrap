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
	GetAadToken(ctx context.Context, clientID, clientSecret, tenantID string, scopes []string) (string, error)
}

func NewAadClient(logger *logrus.Logger) AadClient {
	return &aadClientImpl{
		Logger: logger,
	}
}

type aadClientImpl struct {
	Logger *logrus.Logger
}

func (c *aadClientImpl) GetAadToken(ctx context.Context, clientID, clientSecret, tenantID string, scopes []string) (string, error) {
	if scopes == nil {
		scopes = []string{}
	}
	if len(scopes) < 1 {
		scopes = append(scopes, defaultAKSAADServerScope)
	}

	credential, err := confidential.NewCredFromSecret(clientSecret)
	if err != nil {
		return "", fmt.Errorf("failed to create secret credential from azure.json: %w", err)
	}

	// TODO(cameissner): modify so this works on all clouds later
	authority := fmt.Sprintf(microsoftLoginAuthorityTemplate, tenantID)
	client, err := confidential.New(authority, clientID, credential)
	if err != nil {
		return "", fmt.Errorf("failed to create client from azure.json sp/secret: %w", err)
	}

	c.Logger.WithField("scopes", strings.Join(scopes, ",")).Info("requesting new AAD token")

	authResult, err := retry.DoWithData(func() (confidential.AuthResult, error) {
		authResult, err := client.AcquireTokenByCredential(ctx, scopes)
		if err != nil {
			return confidential.AuthResult{}, err
		}
		return authResult, nil
	}, retry.Context(ctx),
		retry.Attempts(getAadTokenMaxRetries),
		retry.MaxDelay(getAadTokenMaxDelay),
		retry.DelayType(retry.RandomDelay))
	if err != nil {
		return "", fmt.Errorf("failed to acquire token via service principal from AAD: %w", err)
	}

	return authResult.AccessToken, nil
}
