// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package bootstrap

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetErrorType(t *testing.T) {
	cases := []struct {
		name         string
		err          error
		expectedType ErrorType
	}{
		{
			name:         "bootstrap error",
			err:          &BootstrapError{errorType: ErrorTypeGetCredentialFailure},
			expectedType: ErrorTypeGetCredentialFailure,
		},
		{
			name:         "unknown error",
			err:          errors.New("unknown error"),
			expectedType: ErrorTypeUnknown,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.expectedType, GetErrorType(c.err))
		})
	}
}
