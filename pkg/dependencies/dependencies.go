package dependencies

import (
	"context"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/confidential"
)

//-------------------------------------
// dependency injection for testing AcquireTokenByCredential

type AcquireTokenClient interface {
	AcquireTokenByCredential(ctx context.Context, scopes []string) (confidential.AuthResult, error)
}

type AcquireTokenClientImpl struct {
	client *confidential.Client
}

func NewTokenClient(authority, clientID string, credential confidential.Credential) (AcquireTokenClient, error) {
	c, err := confidential.New(authority, clientID, credential)
	return &AcquireTokenClientImpl{client: &c}, err
}

func (t *AcquireTokenClientImpl) AcquireTokenByCredential(ctx context.Context, scopes []string) (confidential.AuthResult, error) {
	authToken, err := t.client.AcquireTokenByCredential(ctx, scopes)
	return authToken, err
}

//-------------------------------------
