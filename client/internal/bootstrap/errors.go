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
	ErrorTypeWriteKubeconfigFailure    ErrorType = "WriteKubeconfigFailure"
)

type BootstrapError struct {
	errorType ErrorType
	inner     error
}

func (e *BootstrapError) Retryable() bool {
	switch e.errorType {
	case ErrorTypeGetAccessTokenFailure,
		ErrorTypeGetInstanceDataFailure,
		ErrorTypeGetAttestedDataFailure,
		ErrorTypeGetNonceFailure,
		ErrorTypeGetCredentialFailure:
		return true
	default:
		return false
	}
}

func (e *BootstrapError) Error() string {
	return fmt.Sprintf("%s: %s", e.errorType, e.inner.Error())
}

func (e *BootstrapError) Type() ErrorType {
	return e.errorType
}

func (e *BootstrapError) Unwrap() error {
	return e.inner
}
