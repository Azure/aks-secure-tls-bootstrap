package errors

import "fmt"

type BootstrapErrorType string

const (
	BootstrapErrorTypeGetAccessTokenFailure       BootstrapErrorType = "GetAccessTokenFailure"
	BootstrapErrorTypeGetServiceClientFailure     BootstrapErrorType = "GetServiceClientFailure"
	BootstrapErrorTypeGetIntanceDataFailure       BootstrapErrorType = "GetInstanceDataFailure"
	BootstrapErrorTypeGetAttestedDataFailure      BootstrapErrorType = "GetAttestedDataFailure"
	BootstrapErrorTypeGetNonceFailure             BootstrapErrorType = "GetNonceFailure"
	BootstrapErrorTypeMakeKubeletClientCSRFailure BootstrapErrorType = "MakeKubeletClientCSRFailure"
	BootstrapErrorTypeGetCredentialFailure        BootstrapErrorType = "GetCredentialFailure"
	BootstrapErrorTypeGenerateKubeconfigFailure   BootstrapErrorType = "GenerateKubeconfigFailure"
	BootstrapErrorTypeWriteKubeconfigFailure      BootstrapErrorType = "WriteKubeconfigFailure"
)

type BootstrapError struct {
	Type  BootstrapErrorType
	Inner error
}

func (e *BootstrapError) Error() string {
	return fmt.Sprintf("%s: %s", e.Type, e.Inner.Error())
}
