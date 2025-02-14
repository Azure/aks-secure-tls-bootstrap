package http

import (
	"net/http"
	"time"

	"github.com/Azure/aks-secure-tls-bootstrap/client/internal/build"
	"github.com/hashicorp/go-retryablehttp"
)

const (
	userAgentHeaderKey = "User-Agent"
)

// NewClient returns a retryablehttp.Client with a custom transport.
func NewClient() *retryablehttp.Client {
	c := retryablehttp.NewClient()
	c.RetryMax = 5
	c.RetryWaitMin = 300 * time.Millisecond
	c.RetryWaitMax = 3 * time.Second

	baseTransport := c.HTTPClient.Transport
	c.HTTPClient.Transport = &customTransport{
		baseTransport: baseTransport,
	}

	return c
}

type customTransport struct {
	baseTransport http.RoundTripper
}

func (t *customTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Set(userAgentHeaderKey, build.GetUserAgentValue())
	return t.baseTransport.RoundTrip(req)
}
