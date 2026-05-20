// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package http

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/Azure/aks-secure-tls-bootstrap/client/internal/build"
	"github.com/Azure/aks-secure-tls-bootstrap/client/internal/log"
	"github.com/hashicorp/go-retryablehttp"
)

const (
	userAgentHeaderKey = "User-Agent"
)

// GetUserAgent returns the common User-Agent header value used in all RPCs and HTTP calls.
func GetUserAgent() string {
	return fmt.Sprintf("aks-secure-tls-bootstrap-client/%s", build.GetVersion())
}

// NewRetryableClient returns a *retryablehttp.Client with a custom transport which injects
// a specialized user agent string into the "User-Agent" header.
func NewRetryableClient(ctx context.Context) *retryablehttp.Client {
	client := retryablehttp.NewClient()
	configureRetryableHTTPLogger(ctx, client)
	configureRetryableHTTPBackoff(client)
	configureCustomTransport(client)
	return client
}

func configureRetryableHTTPLogger(ctx context.Context, client *retryablehttp.Client) {
	client.Logger = log.NewLeveledLoggerShim(log.MustGetLogger(ctx))
}

func configureRetryableHTTPBackoff(client *retryablehttp.Client) {
	// LinearJitterBackoff provides a linear retry policy (1s, 2s, 3s, etc.)
	// with some random jitter applied, bounded by RetryWaitMin and RetryWaitMax.
	client.Backoff = boundedLinearJitterBackoff(3 * time.Second)
	client.RetryWaitMin = 700 * time.Millisecond
	client.RetryWaitMax = 1 * time.Second
	client.RetryMax = 15
}

// provides a wrapper around retryablehttp.LinearJitterBackoff whicih bounds the returned wait time with maxWait,
// ensuring that wait times between individual retries will never exceed maxWait.
func boundedLinearJitterBackoff(maxWait time.Duration) retryablehttp.Backoff {
	return func(minForJitter, maxForJitter time.Duration, attemptNum int, resp *http.Response) time.Duration {
		return min(retryablehttp.LinearJitterBackoff(minForJitter, maxForJitter, attemptNum, resp), maxWait)
	}
}

func configureCustomTransport(client *retryablehttp.Client) {
	transport := client.HTTPClient.Transport
	client.HTTPClient.Transport = &customTransport{
		base: transport,
	}
}

type customTransport struct {
	base http.RoundTripper
}

func (t *customTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Set(userAgentHeaderKey, GetUserAgent())
	return t.base.RoundTrip(req)
}
