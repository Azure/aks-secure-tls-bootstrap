package dependencies

import (
	"context"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/confidential"
)

// replace base import with 'base "github.com/AzureAD/microsoft-authentication-library-for-go/apps/confidential"'
//go:generate ../../../bin/mockgen -copyright_file=../../../hack/copyright_header.txt -destination=../mocks/mock_dependencies.go -package=mocks github.com/Azure/aks-tls-bootstrap-client/pkg/client/dependencies AcquireTokenClient

/*
************************************
dependency injection for testing AcquireTokenByCredential
*/
type AcquireTokenClient interface {
	AcquireTokenByCredential(ctx context.Context, scopes []string) (confidential.AuthResult, error)
}

type AcquireTokenClientImpl struct {
	client *confidential.Client
}

func NewTokenClient(authority, clientID string, credential confidential.Credential) (AcquireTokenClient, error) {
        client, err := confidential.New(authority, clientID, credential)
        if err != nil {
          return nil, fmt.Errorf("failed to construct new confidential client: %w", err)
        }
	return &AcquireTokenClientImpl{client: &client}, nil
	return &AcquireTokenClientImpl{client: &c}, err
}

func (t *AcquireTokenClientImpl) AcquireTokenByCredential(ctx context.Context, scopes []string) (confidential.AuthResult, error) {
	authToken, err := t.client.AcquireTokenByCredential(ctx, scopes)
	return authToken, err
}

/*************************************/
