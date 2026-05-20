// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package http

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestGetUserAgent(t *testing.T) {
	userAgent := GetUserAgent()
	assert.True(t, strings.HasPrefix(userAgent, "aks-secure-tls-bootstrap-client/"))
}

func TestCustomTransport(t *testing.T) {
	var userAgent string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userAgent = r.Header.Get("User-Agent")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	transport := &customTransport{base: http.DefaultTransport}
	client := &http.Client{Transport: transport}

	resp, err := client.Get(server.URL)
	assert.NoError(t, err)
	defer func() {
		assert.NoError(t, resp.Body.Close())
	}()

	assert.True(t, strings.HasPrefix(userAgent, "aks-secure-tls-bootstrap-client/"))
}

func TestBoundedLinearJitterBackoff(t *testing.T) {
	const (
		minWait = 700 * time.Millisecond
		maxWait = 1 * time.Second
		bound   = 3 * time.Second
	)

	cases := []struct {
		name       string
		attemptNum int
	}{
		{
			name:       "first attempt",
			attemptNum: 1,
		},
		{
			name:       "second attempt",
			attemptNum: 2,
		},
		{
			name:       "high attempt count is capped by maxWait",
			attemptNum: 100,
		},
		{
			name:       "very high attempt count is capped by maxWait",
			attemptNum: 10000,
		},
	}

	backoff := boundedLinearJitterBackoff(bound)
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			wait := backoff(minWait, maxWait, c.attemptNum, nil)
			assert.LessOrEqual(t, wait, bound, "wait must never exceed the configured bound")
			assert.GreaterOrEqual(t, wait, time.Duration(0), "wait must be non-negative")
		})
	}
}

func TestBoundedLinearJitterBackoffNeverExceedsBound(t *testing.T) {
	const bound = 50 * time.Millisecond
	backoff := boundedLinearJitterBackoff(bound)

	// underlying LinearJitterBackoff scales with attemptNum; ensure the bound
	// caps the result even when the unbounded value would otherwise be much larger.
	for attempt := 1; attempt <= 20; attempt++ {
		wait := backoff(1*time.Second, 2*time.Second, attempt, nil)
		assert.LessOrEqual(t, wait, bound)
	}
}
