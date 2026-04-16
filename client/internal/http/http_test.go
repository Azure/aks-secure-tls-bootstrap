// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package http

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	azcloud "github.com/Azure/azure-sdk-for-go/sdk/azcore/cloud"
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

func TestGetDefaultAzureClientOpts(t *testing.T) {
	opts := GetDefaultAzureClientOpts()
	assert.Equal(t, int32(10), opts.Retry.MaxRetries)
	assert.Equal(t, 800*time.Millisecond, opts.Retry.RetryDelay)
	assert.Equal(t, 5*time.Second, opts.Retry.MaxRetryDelay)
}

func TestGetDefaultAzureClientOptsWithCloud(t *testing.T) {
	cloudConfig := azcloud.AzurePublic
	opts := GetDefaultAzureClientOptsWithCloud(cloudConfig)
	assert.Equal(t, cloudConfig, opts.Cloud)
	assert.Equal(t, int32(10), opts.Retry.MaxRetries)
	assert.Equal(t, 800*time.Millisecond, opts.Retry.RetryDelay)
	assert.Equal(t, 5*time.Second, opts.Retry.MaxRetryDelay)
}
