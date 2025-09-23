// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package bootstrap

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

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
