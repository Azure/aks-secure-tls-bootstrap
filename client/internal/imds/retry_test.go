package imds

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsRetryableHTTPStatusCode(t *testing.T) {
	cases := []struct {
		name     string
		code     int
		expected bool
	}{
		{
			name:     "code is not retryable",
			code:     http.StatusBadRequest,
			expected: false,
		},
		{
			name:     "code is StatusTooManyRequests",
			code:     http.StatusTooManyRequests,
			expected: true,
		},
		{
			name:     "code is StatusRequestTimeout",
			code:     http.StatusRequestTimeout,
			expected: true,
		},
		{
			name:     "code is StatusNotFound",
			code:     http.StatusNotFound,
			expected: true,
		},
		{
			name:     "code is StatusGone",
			code:     http.StatusGone,
			expected: true,
		},
		{
			name:     "code is StatusInternalServerError",
			code:     http.StatusInternalServerError,
			expected: true,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			retryable := IsRetryableHTTPStatusCode(c.code)
			assert.Equal(t, c.expected, retryable)
		})
	}
}

func TestWrapWithRetryableIMDSStatusCodes(t *testing.T) {
	cases := []struct {
		name               string
		defaultShouldRetry bool
		resp               *http.Response
		err                error
		expected           bool
		expectedErr        error
	}{
		{
			name:               "error is non-nil",
			defaultShouldRetry: false,
			resp:               nil,
			err:                context.DeadlineExceeded,
			expected:           false,
			expectedErr:        context.DeadlineExceeded,
		},
		{
			name:               "error and response are nil",
			defaultShouldRetry: false,
			resp:               nil,
			err:                nil,
			expected:           false,
			expectedErr:        nil,
		},
		{
			name:               "error is nil and response is non-nil, defaultShouldRetry is false and is not a retryable IMDS status code",
			defaultShouldRetry: false,
			resp: &http.Response{
				StatusCode: http.StatusBadRequest,
			},
			err:         nil,
			expected:    false,
			expectedErr: nil,
		},
		{
			name:               "error is nil and response is non-nil, defaultShouldRetry is false and it is a retryable IMDS status code",
			defaultShouldRetry: false,
			resp: &http.Response{
				StatusCode: http.StatusNotFound,
			},
			err:         nil,
			expected:    true,
			expectedErr: nil,
		},
		{
			name:               "error is nil and response is non-nil, defaultShouldRetry is true",
			defaultShouldRetry: true,
			resp: &http.Response{
				StatusCode: http.StatusBadRequest,
			},
			err:         nil,
			expected:    true,
			expectedErr: nil,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			shouldRetry, err := wrapWithRetryableIMDSStatusCodes(c.defaultShouldRetry, c.resp, c.err)
			assert.Equal(t, c.expectedErr, err)
			assert.Equal(t, c.expected, shouldRetry)
		})
	}
}
