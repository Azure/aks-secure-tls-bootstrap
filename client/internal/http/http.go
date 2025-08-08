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

// GetUserAgentValue returns the common User-Agent header value used in all RPCs and HTTP calls.
func GetUserAgentValue() string {
	return fmt.Sprintf("aks-secure-tls-bootstrap-client/%s", build.GetVersion())
}

// NewClient returns an http.Client shimed into a *retryablehttp.Client with a custom transport.
func NewClient(ctx context.Context) *http.Client {
	return NewRetryableClient(ctx).StandardClient()
}

// NewRetryableClient returns a *retryablehttp.Client with a custom transport.
func NewRetryableClient(ctx context.Context) *retryablehttp.Client {
	c := retryablehttp.NewClient()
	c.RetryMax = 5
	c.RetryWaitMin = 300 * time.Millisecond
	c.RetryWaitMax = 3 * time.Second
	transport := c.HTTPClient.Transport
	c.HTTPClient.Transport = &customTransport{
		base: transport,
	}
	c.Logger = log.NewLeveledLoggerShim(log.MustGetLogger(ctx))
	return c
}

type customTransport struct {
	base http.RoundTripper
}

func (t *customTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Set(userAgentHeaderKey, GetUserAgentValue())
	return t.base.RoundTrip(req)
}
