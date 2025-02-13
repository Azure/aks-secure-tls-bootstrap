package http

import (
	"time"

	"github.com/hashicorp/go-retryablehttp"
)

type Client = retryablehttp.Client

type ClientOpt func(*Client)

func WithRetryMax(retryMax int) ClientOpt {
	return func(c *Client) {
		c.RetryMax = retryMax
	}
}

func WithRetryWaitMax(retryWaitMax time.Duration) ClientOpt {
	return func(c *Client) {
		c.RetryWaitMax = retryWaitMax
	}
}

func WithTimeout(timeout time.Duration) ClientOpt {
	return func(c *Client) {
		c.HTTPClient.Timeout = timeout
	}
}

func NewClient(opts ...ClientOpt) *Client {
	client := retryablehttp.NewClient()
	for _, opt := range opts {
		opt(client)
	}
	return client
}
