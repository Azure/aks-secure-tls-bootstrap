// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package bootstrap

import (
	"errors"
	"fmt"
	"net/http"
	"testing"

	"github.com/Azure/go-autorest/autorest/adal"
	"github.com/stretchr/testify/assert"
)

type fakeTokenRefreshError struct {
	resp *http.Response
	err  error
}

var _ adal.TokenRefreshError = (*fakeTokenRefreshError)(nil)

func (e *fakeTokenRefreshError) Response() *http.Response {
	return e.resp
}

func (e *fakeTokenRefreshError) Error() string {
	return e.err.Error()
}

func TestBootstrapError(t *testing.T) {
	cases := []struct {
		name      string
		err       error
		errorType ErrorType
	}{
		{
			name:      "get access token failure",
			err:       errors.New("get access token error"),
			errorType: ErrorTypeGetAccessTokenFailure,
		},
		{
			name:      "get instance data failure",
			err:       errors.New("get instance data error"),
			errorType: ErrorTypeGetInstanceDataFailure,
		},
		{
			name:      "get attested data failure",
			err:       errors.New("get attested data error"),
			errorType: ErrorTypeGetAttestedDataFailure,
		},
		{
			name:      "get nonce failure",
			err:       errors.New("get nonce error"),
			errorType: ErrorTypeGetNonceFailure,
		},
		{
			name:      "get credential failure",
			err:       errors.New("get credential error"),
			errorType: ErrorTypeGetCredentialFailure,
		},
		{
			name:      "get service client failure",
			err:       errors.New("get service client error"),
			errorType: ErrorTypeGetServiceClientFailure,
		},
		{
			name:      "get CSR failure",
			err:       errors.New("get CSR error"),
			errorType: ErrorTypeGetCSRFailure,
		},
		{
			name:      "generate kubeconfig failure",
			err:       errors.New("generate kubeconfig error"),
			errorType: ErrorTypeGenerateKubeconfigFailure,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			bootstrapErr := &bootstrapError{
				errorType: c.errorType,
				inner:     c.err,
			}
			assert.EqualError(t, bootstrapErr, fmt.Sprintf("%s: %s", bootstrapErr.errorType, bootstrapErr.inner.Error()))
		})
	}
}

func TestGetErrorType(t *testing.T) {
	cases := []struct {
		name     string
		err      error
		expected ErrorType
	}{
		{
			name: "error is a GetAccessTokenFailure",
			err: &bootstrapError{
				errorType: ErrorTypeGetAccessTokenFailure,
				inner:     errors.New("get access token failure"),
			},
			expected: ErrorTypeGetAccessTokenFailure,
		},
		{
			name: "error is a GetServiceClientFailure",
			err: &bootstrapError{
				errorType: ErrorTypeGetServiceClientFailure,
				inner:     errors.New("get service client failure"),
			},
			expected: ErrorTypeGetServiceClientFailure,
		},
		{
			name: "error is a GetInstanceDataFailure",
			err: &bootstrapError{
				errorType: ErrorTypeGetInstanceDataFailure,
				inner:     errors.New("get instance data failure"),
			},
			expected: ErrorTypeGetInstanceDataFailure,
		},
		{
			name: "error is a GetAttestedDataFailure",
			err: &bootstrapError{
				errorType: ErrorTypeGetAttestedDataFailure,
				inner:     errors.New("get attested data failure"),
			},
			expected: ErrorTypeGetAttestedDataFailure,
		},
		{
			name: "error is a GetNonceFailure",
			err: &bootstrapError{
				errorType: ErrorTypeGetNonceFailure,
				inner:     errors.New("get nonce failure"),
			},
			expected: ErrorTypeGetNonceFailure,
		},
		{
			name: "error is a GetCSRFailure",
			err: &bootstrapError{
				errorType: ErrorTypeGetCSRFailure,
				inner:     errors.New("get CSR failure"),
			},
			expected: ErrorTypeGetCSRFailure,
		},
		{
			name: "error is a GetCredentialFailure",
			err: &bootstrapError{
				errorType: ErrorTypeGetCredentialFailure,
				inner:     errors.New("get credential failure"),
			},
			expected: ErrorTypeGetCredentialFailure,
		},
		{
			name: "error is a GenerateKubeconfigFailure",
			err: &bootstrapError{
				errorType: ErrorTypeGenerateKubeconfigFailure,
				inner:     errors.New("generate kubeconfig failure"),
			},
			expected: ErrorTypeGenerateKubeconfigFailure,
		},
		{
			name:     "error is not an instance of bootstrapError",
			err:      errors.New("an error"),
			expected: "",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.expected, GetErrorType(c.err))
		})
	}
}
