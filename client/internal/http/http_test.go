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
	cases := []struct {
		name   string
		assert func(t *testing.T)
	}{
		{
			name: "returns expected user agent string",
			assert: func(t *testing.T) {
				assert.True(t, strings.HasPrefix(GetUserAgent(), "aks-secure-tls-bootstrap-client/"))
			},
		},
		{
			name: "User-Agent header is set on outgoing requests via customTransport",
			assert: func(t *testing.T) {
				var receivedUA string
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					receivedUA = r.Header.Get("User-Agent")
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

				assert.True(t, strings.HasPrefix(receivedUA, "aks-secure-tls-bootstrap-client/"))
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			c.assert(t)
		})
	}
}

func TestGetDefaultAzureClientOpts(t *testing.T) {
	cases := []struct {
		name   string
		assert func(t *testing.T)
	}{
		{
			name: "MaxRetries is 10",
			assert: func(t *testing.T) {
				opts := GetDefaultAzureClientOpts()
				assert.Equal(t, int32(10), opts.Retry.MaxRetries)
			},
		},
		{
			name: "RetryDelay is 800ms",
			assert: func(t *testing.T) {
				opts := GetDefaultAzureClientOpts()
				assert.Equal(t, 800*time.Millisecond, opts.Retry.RetryDelay)
			},
		},
		{
			name: "MaxRetryDelay is 5s",
			assert: func(t *testing.T) {
				opts := GetDefaultAzureClientOpts()
				assert.Equal(t, 5*time.Second, opts.Retry.MaxRetryDelay)
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			c.assert(t)
		})
	}
}

func TestGetDefaultAzureClientOptsWithCloud(t *testing.T) {
	cases := []struct {
		name        string
		cloudConfig azcloud.Configuration
		assert      func(t *testing.T, cloudConfig azcloud.Configuration)
	}{
		{
			name: "cloud config is set on returned options",
			cloudConfig: azcloud.Configuration{
				ActiveDirectoryAuthorityHost: "https://login.microsoftonline.com/",
				Services: map[azcloud.ServiceName]azcloud.ServiceConfiguration{
					azcloud.ResourceManager: {
						Audience: "https://management.azure.com/",
						Endpoint: "https://management.azure.com",
					},
				},
			},
			assert: func(t *testing.T, cloudConfig azcloud.Configuration) {
				opts := GetDefaultAzureClientOptsWithCloud(cloudConfig)
				assert.Equal(t, cloudConfig.ActiveDirectoryAuthorityHost, opts.Cloud.ActiveDirectoryAuthorityHost)
				assert.Equal(t, cloudConfig.Services, opts.Cloud.Services)
			},
		},
		{
			name: "default retry options are preserved with cloud config",
			cloudConfig: azcloud.Configuration{
				ActiveDirectoryAuthorityHost: "https://login.chinacloudapi.cn/",
			},
			assert: func(t *testing.T, cloudConfig azcloud.Configuration) {
				opts := GetDefaultAzureClientOptsWithCloud(cloudConfig)
				assert.Equal(t, int32(10), opts.Retry.MaxRetries)
				assert.Equal(t, 800*time.Millisecond, opts.Retry.RetryDelay)
				assert.Equal(t, 5*time.Second, opts.Retry.MaxRetryDelay)
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			c.assert(t, c.cloudConfig)
		})
	}
}
