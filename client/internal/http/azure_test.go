package http

import (
	"context"
	"net/http"
	"testing"
	"time"

	azcloud "github.com/Azure/azure-sdk-for-go/sdk/azcore/cloud"
	"github.com/stretchr/testify/assert"
)

func TestGetDefaultAzureClientOptsWithCloud(t *testing.T) {
	cloudConfig := azcloud.AzurePublic
	opts := GetDefaultAzureClientOptsWithCloud(cloudConfig)
	assert.Equal(t, cloudConfig, opts.Cloud)
	assert.Equal(t, int32(15), opts.Retry.MaxRetries)
	assert.Equal(t, 800*time.Millisecond, opts.Retry.RetryDelay)
	assert.Equal(t, 3*time.Second, opts.Retry.MaxRetryDelay)
}

func TestGetManagedIdentityClientOpts(t *testing.T) {
	opts := GetManagedIdentityClientOpts()

	assert.Equal(t, int32(15), opts.Retry.MaxRetries)
	assert.Equal(t, 800*time.Millisecond, opts.Retry.RetryDelay)
	assert.Equal(t, 3*time.Second, opts.Retry.MaxRetryDelay)

	expectedStatusCodes := []int{
		http.StatusBadRequest,                    // 400
		http.StatusNotFound,                      // 404
		http.StatusGone,                          // 410
		http.StatusTooManyRequests,               // 429
		http.StatusInternalServerError,           // 500
		http.StatusNotImplemented,                // 501
		http.StatusBadGateway,                    // 502
		http.StatusServiceUnavailable,            // 503
		http.StatusGatewayTimeout,                // 504
		http.StatusHTTPVersionNotSupported,       // 505
		http.StatusVariantAlsoNegotiates,         // 506
		http.StatusInsufficientStorage,           // 507
		http.StatusLoopDetected,                  // 508
		http.StatusNotExtended,                   // 510
		http.StatusNetworkAuthenticationRequired, // 511
	}
	for _, statusCode := range expectedStatusCodes {
		assert.Contains(t, opts.Retry.StatusCodes, statusCode)
	}
}

func TestGetDefaultIMDSRetryPolicy(t *testing.T) {
	canceledContext := func() context.Context {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		return ctx
	}

	cases := []struct {
		name        string
		ctx         context.Context
		resp        *http.Response
		err         error
		expected    bool
		expectedErr error
	}{
		{
			name:     "context is canceled",
			ctx:      canceledContext(),
			resp:     nil,
			err:      nil,
			expected: false,
			// ensure we properly propagate context errors caught by retryablehttp.DefaultRetryPolicy
			expectedErr: context.Canceled,
		},
		{
			name:     "status code is not retryable",
			ctx:      context.Background(),
			resp:     &http.Response{StatusCode: http.StatusBadRequest},
			expected: false,
		},
		{
			name:     "status code is StatusTooManyRequests",
			ctx:      context.Background(),
			resp:     &http.Response{StatusCode: http.StatusTooManyRequests},
			expected: true,
		},
		{
			name:     "status code is StatusNotFound",
			ctx:      context.Background(),
			resp:     &http.Response{StatusCode: http.StatusNotFound},
			expected: true,
		},
		{
			name:     "status code is StatusGone",
			ctx:      context.Background(),
			resp:     &http.Response{StatusCode: http.StatusGone},
			expected: true,
		},
		{
			name:     "status code is StatusInternalServerError",
			ctx:      context.Background(),
			resp:     &http.Response{StatusCode: http.StatusInternalServerError},
			expected: true,
		},
	}

	checkRetry := GetDefaultIMDSRetryPolicy()
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			shouldRetry, err := checkRetry(c.ctx, c.resp, c.err)
			assert.Equal(t, c.expectedErr, err)
			assert.Equal(t, c.expected, shouldRetry)
		})
	}
}
