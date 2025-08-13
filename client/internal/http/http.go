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

// NewClient returns an http.Client shimmed into a *retryablehttp.Client with a custom transport.
func NewClient(ctx context.Context) *http.Client {
	return NewRetryableClient(ctx).StandardClient()
}

// NewRetryableClient returns a *retryablehttp.Client with a custom transport.
func NewRetryableClient(ctx context.Context) *retryablehttp.Client {
	client := retryablehttp.NewClient()
	configureLogger(ctx, client)
	configureRetryPolicy(client)
	configureTransport(client)
	return client
}

func configureLogger(ctx context.Context, client *retryablehttp.Client) {
	client.Logger = log.NewLeveledLoggerShim(log.MustGetLogger(ctx))
}

func configureRetryPolicy(client *retryablehttp.Client) {
	// retryablehttp.DefaultBackoff implements an exponential backoff strategy
	// bounded by RetryWaitMin + RetryWaitMax. It will also attempt to parse out and respect any
	// Retry-After header from the server's response.
	client.Backoff = retryablehttp.DefaultBackoff
	client.RetryMax = 5
	client.RetryWaitMin = 300 * time.Millisecond
	client.RetryWaitMax = 3 * time.Second
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
