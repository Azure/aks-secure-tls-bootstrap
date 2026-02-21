// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package imds

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	internalhttp "github.com/Azure/aks-secure-tls-bootstrap/client/internal/http"
	"github.com/Azure/aks-secure-tls-bootstrap/client/internal/log"
	"github.com/stretchr/testify/assert"
)

func TestCallIMDS(t *testing.T) {
	cases := []struct {
		name            string
		setupTestServer func(map[string]string) *httptest.Server
		params          map[string]string
	}{
		{
			name:   "should specify Metadata:True in the request headers",
			params: map[string]string{},
			setupTestServer: func(params map[string]string) *httptest.Server {
				return mockIMDSWithAssertions(t, "{}", func(r *http.Request) {
					assert.Equal(t, "True", r.Header.Get("Metadata"))
				})
			},
		},
		{
			name:   "there aren't query parameters",
			params: map[string]string{},
			setupTestServer: func(params map[string]string) *httptest.Server {
				return mockIMDSWithAssertions(t, "{}", func(r *http.Request) {
					assert.Empty(t, r.URL.Query())
				})
			},
		},
		{
			name: "there are query parameters",
			params: map[string]string{
				"a": "1",
				"b": "2",
				"c": "3",
			},
			setupTestServer: func(params map[string]string) *httptest.Server {
				imds := mockIMDSWithAssertions(t, "{}", func(r *http.Request) {
					queryParameters := r.URL.Query()
					for param, expectedValue := range params {
						assert.Equal(t, expectedValue, queryParameters.Get(param))
					}
				})

				return imds
			},
		},
	}

	ctx := log.NewTestContext()

	for _, c := range cases {
		imdsClient := &client{
			httpClient: internalhttp.NewRetryableClient(ctx).StandardClient(),
		}
		imds := c.setupTestServer(c.params)
		defer imds.Close()

		err := imdsClient.callIMDS(ctx, imds.URL, c.params, &VMInstanceData{})
		assert.NoError(t, err)
	}
}

func TestGetInstanceData(t *testing.T) {
	cases := []struct {
		name               string
		json               string
		expectedErr        string
		expectedResourceID string
	}{
		{
			name:               "should call the correct IMDS endpoint with the correct query parameters",
			json:               `{"compute":{"resourceId": "resourceId"}}`,
			expectedErr:        "",
			expectedResourceID: "resourceId",
		},
		{
			name:               "unable parse instance data response from IMDS",
			json:               "malformed",
			expectedErr:        "failed to unmarshal IMDS data",
			expectedResourceID: "",
		},
	}

	ctx := log.NewTestContext()

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			imds := mockIMDSWithAssertions(t, c.json, func(r *http.Request) {
				assert.Equal(t, "/metadata/instance", r.URL.Path)
				queryParameters := r.URL.Query()
				assert.Equal(t, apiVersion, queryParameters.Get("api-version"))
				assert.Equal(t, "json", queryParameters.Get("format"))
			})
			defer imds.Close()

			imdsClient := &client{
				httpClient: internalhttp.NewRetryableClient(ctx).StandardClient(),
				baseURL:    imds.URL,
			}

			instanceData, err := imdsClient.GetInstanceData(ctx)
			if c.expectedErr != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), c.expectedErr)
				assert.Nil(t, instanceData)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, instanceData)
				assert.Equal(t, c.expectedResourceID, instanceData.Compute.ResourceID)
			}
		})
	}
}

func TestGetAttestedData(t *testing.T) {
	cases := []struct {
		name              string
		responseBody      string
		expectedErr       string
		expectedSignature string
	}{
		{
			name:              "should call the correct IMDS endpoint with the correct query parameters",
			responseBody:      `{"signature":"signature"}`,
			expectedErr:       "",
			expectedSignature: "signature",
		},
		{
			name:              "unable to parse attested data response from IMDS",
			responseBody:      "malformed",
			expectedErr:       "failed to unmarshal IMDS data",
			expectedSignature: "",
		},
	}

	ctx := log.NewTestContext()

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			imds := mockIMDSWithAssertions(t, c.responseBody, func(r *http.Request) {
				assert.Equal(t, "/metadata/attested/document", r.URL.Path)
				queryParameters := r.URL.Query()
				assert.Equal(t, apiVersion, queryParameters.Get("api-version"))
				assert.Equal(t, "json", queryParameters.Get("format"))
				assert.Equal(t, "nonce", queryParameters.Get("nonce"))
			})
			defer imds.Close()

			imdsClient := &client{
				httpClient: internalhttp.NewRetryableClient(ctx).StandardClient(),
				baseURL:    imds.URL,
			}

			attestedData, err := imdsClient.GetAttestedData(ctx, "nonce")
			if c.expectedErr != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), c.expectedErr)
				assert.Nil(t, attestedData)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, attestedData)
				assert.Equal(t, c.expectedSignature, attestedData.Signature)
			}
		})
	}
}

func mockIMDSWithAssertions(t *testing.T, response string, assertions func(r *http.Request)) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.True(t, strings.HasPrefix(r.Header.Get("User-Agent"), "aks-secure-tls-bootstrap-client/"))
		assertions(r)
		w.WriteHeader(http.StatusOK)
		_, err := fmt.Fprintln(w, response)
		assert.NoError(t, err)
	}))
}
