// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package bootstrap

import "errors"

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
	ErrorTypeUnknown                   ErrorType = "Unknown"
)

type BootstrapError struct {
	errorType ErrorType
	inner     error
}

func (e *BootstrapError) Error() string {
	return e.inner.Error()
}

func GetErrorType(err error) ErrorType {
	var bootstrapError *BootstrapError
	if errors.As(err, &bootstrapError) {
		return bootstrapError.errorType
	}
	return ErrorTypeUnknown
}
