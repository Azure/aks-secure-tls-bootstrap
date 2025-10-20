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

// UserAgent returns the common User-Agent header value used in all RPCs and HTTP calls.
func UserAgent() string {
	return fmt.Sprintf("aks-secure-tls-bootstrap-client/%s", build.GetVersion())
}

// NewRetryableClient returns a *retryablehttp.Client with a custom transport.
func NewRetryableClient(ctx context.Context) *retryablehttp.Client {
	client := retryablehttp.NewClient()
	configureLogger(ctx, client)
	configureBackoff(client)
	configureTransport(client)
	return client
}

func configureLogger(ctx context.Context, client *retryablehttp.Client) {
	client.Logger = log.NewLeveledLoggerShim(log.MustGetLogger(ctx))
}

func configureBackoff(client *retryablehttp.Client) {
	// LinearJitterBackoff provides a linear retry policy (1s, 2s, 3s, etc.)
	// with some random jitter applied, bounded by RetryWaitMin and RetryWaitMax.
	client.Backoff = retryablehttp.LinearJitterBackoff
	client.RetryWaitMin = 800 * time.Millisecond
	client.RetryWaitMax = 1200 * time.Millisecond
	client.RetryMax = 10
}

func configureTransport(client *retryablehttp.Client) {
	transport := client.HTTPClient.Transport
	client.HTTPClient.Transport = &customTransport{
		base: transport,
	}
}

type customTransport struct {
	base http.RoundTripper
}

func (t *customTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Set(userAgentHeaderKey, UserAgent())
	return t.base.RoundTrip(req)
}
