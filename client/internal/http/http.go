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
	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	azcloud "github.com/Azure/azure-sdk-for-go/sdk/azcore/cloud"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/hashicorp/go-retryablehttp"
)

const (
	userAgentHeaderKey = "User-Agent"
)

// GetUserAgent returns the common User-Agent header value used in all RPCs and HTTP calls.
func GetUserAgent() string {
	return fmt.Sprintf("aks-secure-tls-bootstrap-client/%s", build.GetVersion())
}

func GetManagedIdentityClientOpts() azcore.ClientOptions {
	opts := defaultAzureClientOpts()
	opts.Retry.StatusCodes = []int{
		// We allow retrying on StatusBadRequest since this will be the returned status code when IMDS dsoesn't yet recognize
		// that the identity we request a token for has been attached to the underlying VM - there can seemingly be a delay
		// in propagation from Entra ID to IMDS with respect to identity attachment. This is outside of the official IMDS
		// retry guidance, but something we need to explicitly handle for
		http.StatusBadRequest, // 400

		// IMDS docs recommend retrying 404, 410, 429 and 5xx
		// https://learn.microsoft.com/entra/identity/managed-identities-azure-resources/how-to-use-vm-token#error-handling
		// taken from track2 managed identity client implementation: https://github.com/Azure/azure-sdk-for-go/blob/50d3c2154b3415f02ad311b89ea86d926c3399d9/sdk/azidentity/managed_identity_client.go#L61
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
	return opts
}

func GetDefaultAzureClientOptsWithCloud(cloudConfig azcloud.Configuration) azcore.ClientOptions {
	opts := defaultAzureClientOpts()
	opts.Cloud = cloudConfig
	return opts
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

func defaultAzureClientOpts() azcore.ClientOptions {
	return azcore.ClientOptions{
		// Retry allows us to override exponential backoff parameters for talking to
		// Azure services using a track2 SDK client, such as Entra ID.
		// All options not overriden will be defaulted accordingly at request time.
		// We only override a minimal set of fields to allow track2 clients to intelligently
		// determinie the best retry configuration based on the scenario (such as IMDS vs. Entra ID, etc.)
		Retry: policy.RetryOptions{
			MaxRetries: 15,
			RetryDelay: 800 * time.Millisecond,
			// this is primarily to prevent deep exponential backoff loops
			// from causing too much delay (we take a more "aggressive" retry strategy to minimze bootstrap latency)
			MaxRetryDelay: 5 * time.Second,
		},
	}
}

type customTransport struct {
	base http.RoundTripper
}

func (t *customTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Set(userAgentHeaderKey, GetUserAgent())
	return t.base.RoundTrip(req)
}
