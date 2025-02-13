// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package aad

import (
	"context"
	"testing"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/confidential"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

type fakeTokenAcquirer struct {
	AcquireTokenByCredentialFunc func(ctx context.Context, scopes []string, opts ...confidential.AcquireByCredentialOption) (confidential.AuthResult, error)
}

func (a *fakeTokenAcquirer) AcquireTokenByCredential(ctx context.Context, scopes []string, opts ...confidential.AcquireByCredentialOption) (confidential.AuthResult, error) {
	return a.AcquireTokenByCredentialFunc(ctx, scopes, opts...)
}

func TestAAD(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "aad suite")
}
