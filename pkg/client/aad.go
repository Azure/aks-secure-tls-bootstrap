// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package client

// if mock_aad.go errors after running 'make generate' change the base import to ' base "github.com/AzureAD/microsoft-authentication-library-for-go/apps/confidential" `
//go:generate ../../bin/mockgen -copyright_file=../../hack/copyright_header.txt -destination=./mocks/mock_aad.go -package=mocks github.com/Azure/aks-tls-bootstrap-client/pkg/client AadClient,TokenAcquirer

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

func NewAadClient(logger *logrus.Logger, aquireFunc aadTokenAcquirerFunc) AadClient {
	return &aadClientImpl{
		Logger:            logger,
		tokenAcquirerFunc: aquireFunc,
	}
}

type TokenAcquirer interface {
	Acquire(ctx context.Context, scopes []string) (confidential.AuthResult, error)
}

type aadTokenAcquirer struct {
	confidential.Client
}

type aadTokenAcquirerFunc func(authority, clientID, clientSecret string) (TokenAcquirer, error)

func newAadTokenAcquirer(authority, clientID, clientSecret string) (TokenAcquirer, error) {
	credential, err := confidential.NewCredFromSecret(clientSecret)
	if err != nil {
		return nil, fmt.Errorf("failed to create secret credential from azure.json: %w", err)
	}
	client, err := confidential.New(authority, clientID, credential)
	if err != nil {
		return nil, fmt.Errorf("failed to create client from azure.json sp/secret: %w", err)
	}
	return &aadTokenAcquirer{client}, nil
}

func (a *aadTokenAcquirer) Acquire(ctx context.Context, scopes []string) (confidential.AuthResult, error) {
	return a.AcquireTokenByCredential(ctx, scopes)
}

type aadClientImpl struct {
	Logger            *logrus.Logger
	tokenAcquirerFunc aadTokenAcquirerFunc
}

func (c *aadClientImpl) GetAadToken(ctx context.Context, clientID, clientSecret, tenantID, resource string) (string, error) {
	scopes := []string{
		fmt.Sprintf("%s/.default", resource),
	}
	c.Logger.WithField("scopes", strings.Join(scopes, ",")).Info("requesting new AAD token")

	authority := fmt.Sprintf(microsoftLoginAuthorityTemplate, tenantID)

	tokenAcquirer, err := c.tokenAcquirerFunc(authority, clientID, clientSecret)
	if err != nil {
		return "", fmt.Errorf("unable to construct new AAD token acquirer: %w", err)
	}

	authResult, err := retry.DoWithData(func() (confidential.AuthResult, error) {
		res, err := tokenAcquirer.Acquire(ctx, scopes)
		if err != nil {
			return confidential.AuthResult{}, err
		}
		return res, nil
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
