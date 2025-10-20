// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package imds

import (
	"context"
	"net/http"

	"github.com/hashicorp/go-retryablehttp"
)

func IsRetryableHTTPStatusCode(code int) bool {
	// 4XX retry status codes specific to IMDS - taken from adal's token refresh implementation
	if code == http.StatusTooManyRequests || code == http.StatusRequestTimeout ||
		code == http.StatusNotFound || code == http.StatusGone {
		return true
	}
	return code >= http.StatusInternalServerError
}

// getCheckRetry can be applied to a retryablehttp.Client to correctly handle HTTP status codes
// according to guidance from IMDS + adal's token refresh implementation
func getCheckRetry() retryablehttp.CheckRetry {
	return func(ctx context.Context, resp *http.Response, err error) (bool, error) {
		defaultShouldRetry, err := retryablehttp.DefaultRetryPolicy(ctx, resp, err)
		if err != nil {
			// retryablehttp.DefaultRetryPolicy will only bubble up context errors, which we should always halt on
			return false, err
		}
		if resp == nil {
			// fall back to default logic if we can't check the status code
			return defaultShouldRetry, nil
		}
		return defaultShouldRetry || IsRetryableHTTPStatusCode(resp.StatusCode), nil
	}
}
