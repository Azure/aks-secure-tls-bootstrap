// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package bootstrap

import (
	"fmt"

	internalhttp "github.com/Azure/aks-secure-tls-bootstrap/client/internal/http"
	"github.com/Azure/go-autorest/autorest/adal"
)

type ErrorType string

const (
	ErrorTypeGetAccessTokenFailure     ErrorType = "GetAccessTokenFailure"
	ErrorTypeGetServiceClientFailure   ErrorType = "GetServiceClientFailure"
	ErrorTypeGetInstanceDataFailure    ErrorType = "GetInstanceDataFailure"
	ErrorTypeGetAttestedDataFailure    ErrorType = "GetAttestedDataFailure"
	ErrorTypeGetNonceFailure           ErrorType = "GetNonceFailure"
	ErrorTypeGetCSRFailure             ErrorType = "GetCSRFailure"
	ErrorTypeGetCredentialFailure      ErrorType = "GetCredentialFailure"
	ErrorTypeGenerateKubeconfigFailure ErrorType = "GenerateKubeconfigFailure"
)

type ErrorLog map[ErrorType]int

type bootstrapError struct {
	errorType ErrorType
	retryable bool
	inner     error
}

func (e *bootstrapError) Error() string {
	return fmt.Sprintf("%s: %s", e.errorType, e.inner.Error())
}

func (e *bootstrapError) Unwrap() error {
	return e.inner
}

func makeNonRetryableGetAccessTokenFailure(err error) error {
	return &bootstrapError{
		errorType: ErrorTypeGetAccessTokenFailure,
		retryable: false,
		inner:     err,
	}
}

func tokenRefreshErrorToGetAccessTokenFailure(err error) *bootstrapError {
	// optimistically start by considering the error is retryable
	retryable := true

	refreshErr, ok := err.(adal.TokenRefreshError)
	if ok {
		response := refreshErr.Response()
		if response != nil {
			// only considering marking as non-retryable if we have a status code
			retryable = internalhttp.IsRetryableHTTPStatusCode(response.StatusCode)
		}
	}

	return &bootstrapError{
		errorType: ErrorTypeGetAccessTokenFailure,
		retryable: retryable,
		inner:     fmt.Errorf("obtaining fresh access token: %w", err),
	}
}
