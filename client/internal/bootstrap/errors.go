package bootstrap

import "fmt"

type ErrorType string

const (
	ErrorTypeGetAccessTokenFailure       ErrorType = "GetAccessTokenFailure"
	ErrorTypeGetServiceClientFailure     ErrorType = "GetServiceClientFailure"
	ErrorTypeGetIntanceDataFailure       ErrorType = "GetInstanceDataFailure"
	ErrorTypeGetAttestedDataFailure      ErrorType = "GetAttestedDataFailure"
	ErrorTypeGetNonceFailure             ErrorType = "GetNonceFailure"
	ErrorTypeMakeKubeletClientCSRFailure ErrorType = "MakeKubeletClientCSRFailure"
	ErrorTypeGetCredentialFailure        ErrorType = "GetCredentialFailure"
	ErrorTypeGenerateKubeconfigFailure   ErrorType = "GenerateKubeconfigFailure"
	ErrorTypeWriteKubeconfigFailure      ErrorType = "WriteKubeconfigFailure"
)

type BootstrapError struct {
	errorType ErrorType
	inner     error
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
