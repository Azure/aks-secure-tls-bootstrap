// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package bootstrap

import "fmt"

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
