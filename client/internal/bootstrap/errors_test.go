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

type fakeRefreshError struct {
	response *http.Response
	err      error
}

var _ adal.TokenRefreshError = (*fakeRefreshError)(nil)

func (e *fakeRefreshError) Response() *http.Response {
	return e.response
}

func (e *fakeRefreshError) Error() string {
	return e.err.Error()
}

func TestBootstrapError(t *testing.T) {
	cases := []struct {
		name      string
		err       error
		retryable bool
		errorType ErrorType
	}{
		{
			name:      "get access token failure",
			err:       errors.New("get access token error"),
			retryable: true,
			errorType: ErrorTypeGetAccessTokenFailure,
		},
		{
			name:      "get instance data failure",
			err:       errors.New("get instance data error"),
			retryable: true,
			errorType: ErrorTypeGetInstanceDataFailure,
		},
		{
			name:      "get attested data failure",
			err:       errors.New("get attested data error"),
			retryable: true,
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
				retryable: c.retryable,
				inner:     c.err,
			}

			assert.EqualError(t, bootstrapErr, fmt.Sprintf("%s: %s", bootstrapErr.errorType, bootstrapErr.inner.Error()))
			assert.Equal(t, bootstrapErr.retryable, c.retryable)
		})
	}
}

func TestTokenRefreshErrorToGetAccessTokenFailure(t *testing.T) {
	cases := []struct {
		name        string
		err         error
		expectedErr *bootstrapError
	}{
		{
			name: "error is not an adal.TokenRefreshError",
			err:  errors.New("unexpected error"),
			expectedErr: &bootstrapError{
				errorType: ErrorTypeGetAccessTokenFailure,
				retryable: true,
				inner:     errors.New("obtaining fresh access token: unexpected error"),
			},
		},
		{
			name: "error is an adal.TokenRefreshError with nil response",
			err: &fakeRefreshError{
				response: nil,
				err:      errors.New("refresh error"),
			},
			expectedErr: &bootstrapError{
				errorType: ErrorTypeGetAccessTokenFailure,
				retryable: true,
				inner:     errors.New("obtaining fresh access token: refresh error"),
			},
		},
		{
			name: "error is an adal.TokenRefreshError with 5XX response",
			err: &fakeRefreshError{
				response: &http.Response{
					StatusCode: http.StatusInternalServerError,
				},
				err: errors.New("refresh error"),
			},
			expectedErr: &bootstrapError{
				errorType: ErrorTypeGetAccessTokenFailure,
				retryable: true,
				inner:     errors.New("obtaining fresh access token: refresh error"),
			},
		},
		{
			name: "error is an adal.TokenRefreshError with 429 response",
			err: &fakeRefreshError{
				response: &http.Response{
					StatusCode: http.StatusTooManyRequests,
				},
				err: errors.New("refresh error"),
			},
			expectedErr: &bootstrapError{
				errorType: ErrorTypeGetAccessTokenFailure,
				retryable: true,
				inner:     errors.New("obtaining fresh access token: refresh error"),
			},
		},
		{
			name: "error is an adal.TokenRefreshError with 404 response",
			err: &fakeRefreshError{
				response: &http.Response{
					StatusCode: http.StatusNotFound,
				},
				err: errors.New("refresh error"),
			},
			expectedErr: &bootstrapError{
				errorType: ErrorTypeGetAccessTokenFailure,
				retryable: true,
				inner:     errors.New("obtaining fresh access token: refresh error"),
			},
		},
		{
			name: "error is an adal.TokenRefreshError with non-retryable response",
			err: &fakeRefreshError{
				response: &http.Response{
					StatusCode: http.StatusUnauthorized,
				},
				err: errors.New("unauthorized"),
			},
			expectedErr: &bootstrapError{
				errorType: ErrorTypeGetAccessTokenFailure,
				retryable: false,
				inner:     errors.New("obtaining fresh access token: unauthorized"),
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := tokenRefreshErrorToGetAccessTokenFailure(c.err)
			var bootstrapErr *bootstrapError
			assert.True(t, errors.As(err, &bootstrapErr))
			assert.Equal(t, c.expectedErr.errorType, bootstrapErr.errorType)
			assert.Equal(t, c.expectedErr.retryable, bootstrapErr.retryable)
			assert.EqualError(t, c.expectedErr.inner, bootstrapErr.inner.Error())
		})
	}
}
