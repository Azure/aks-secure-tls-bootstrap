package http

import (
	"context"
	"net/http"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	azcloud "github.com/Azure/azure-sdk-for-go/sdk/azcore/cloud"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/hashicorp/go-retryablehttp"
	"github.com/samber/lo"
)

func GetManagedIdentityClientOpts() azcore.ClientOptions {
	opts := defaultAzureClientOpts()
	opts.Retry.StatusCodes = defaultRetryableIMDSStatusCodes()

	// We allow retrying on StatusBadRequest (400) since this will be the returned status code when IMDS dsoesn't yet recognize
	// that the identity we request a token for has been attached to the underlying VM - there can seemingly be a delay
	// in propagation from Entra ID to IMDS with respect to identity attachment. This is outside of the official IMDS
	// retry guidance, but something we need to explicitly handle for
	opts.Retry.StatusCodes = append(opts.Retry.StatusCodes, http.StatusBadRequest)

	return opts
}

func GetDefaultAzureClientOptsWithCloud(cloudConfig azcloud.Configuration) azcore.ClientOptions {
	opts := defaultAzureClientOpts()
	opts.Cloud = cloudConfig
	return opts
}

// GetDefaultIMDSRetryPolicy can be applied to a retryablehttp.Client to correctly handle HTTP status codes
// according to IMDS retry guidance. Note that this retry policy does NOT handle extra status codes
// that would normally be considered retryable when acquiring MSI access tokens from IMDS.
func GetDefaultIMDSRetryPolicy() retryablehttp.CheckRetry {
	retryableIMDSStatusCodes := lo.SliceToMap(defaultRetryableIMDSStatusCodes(), func(code int) (int, bool) {
		return code, true
	})
	return func(ctx context.Context, resp *http.Response, err error) (bool, error) {
		defaultShouldRetry, retryErr := retryablehttp.DefaultRetryPolicy(ctx, resp, err)
		if retryErr != nil {
			// retryErr will only be non-nil on context cancelation
			return false, retryErr
		}
		if defaultShouldRetry {
			return true, nil
		}
		if resp == nil {
			return false, nil
		}
		return retryableIMDSStatusCodes[resp.StatusCode], nil
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
			MaxRetryDelay: 3 * time.Second,
		},
	}
}

func defaultRetryableIMDSStatusCodes() []int {
	return []int{
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
}
