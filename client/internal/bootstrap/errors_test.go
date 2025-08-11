package bootstrap

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBootstrapErrorRetryable(t *testing.T) {
	cases := []struct {
		name     string
		err      *BootstrapError
		expected bool
	}{
		{
			name:     "get access token failure should be retryable",
			err:      &BootstrapError{errorType: ErrorTypeGetAccessTokenFailure, inner: errors.New("get access token error")},
			expected: true,
		},
		{
			name:     "get instance data failure should be retryable",
			err:      &BootstrapError{errorType: ErrorTypeGetInstanceDataFailure, inner: errors.New("get instance data error")},
			expected: true,
		},
		{
			name:     "get attested data failure should be retryable",
			err:      &BootstrapError{errorType: ErrorTypeGetAttestedDataFailure, inner: errors.New("get attested data error")},
			expected: true,
		},
		{
			name:     "get nonce failure should be retryable",
			err:      &BootstrapError{errorType: ErrorTypeGetNonceFailure, inner: errors.New("get nonce error")},
			expected: true,
		},
		{
			name:     "get credential failure should be retryable",
			err:      &BootstrapError{errorType: ErrorTypeGetCredentialFailure, inner: errors.New("get credential error")},
			expected: true,
		},
		{
			name:     "get service client error should not be retryable",
			err:      &BootstrapError{errorType: ErrorTypeGetServiceClientFailure, inner: errors.New("get service client error")},
			expected: false,
		},
		{
			name:     "get CSR failure should not be retryable",
			err:      &BootstrapError{errorType: ErrorTypeGetCSRFailure, inner: errors.New("get CSR error")},
			expected: false,
		},
		{
			name:     "generate kubeconfig error should not be retryable",
			err:      &BootstrapError{errorType: ErrorTypeGenerateKubeconfigFailure, inner: errors.New("generate kubeconfig error")},
			expected: false,
		},
		{
			name:     "write kubeconfig error should not be retryable",
			err:      &BootstrapError{errorType: ErrorTypeWriteKubeconfigFailure, inner: errors.New("write kubeconfig error")},
			expected: false,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.expected, c.err.Retryable())
		})
	}
}
