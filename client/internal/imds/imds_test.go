// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package imds

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	internalhttp "github.com/Azure/aks-secure-tls-bootstrap/client/internal/http"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

func TestCallIMDS(t *testing.T) {
	tests := []struct {
		name      string
		setupFunc func(map[string]string) *httptest.Server
		params    map[string]string
	}{
		{
			name:   "should specify Metadata:True in the request headers",
			params: map[string]string{},
			setupFunc: func(params map[string]string) *httptest.Server {
				return mockIMDSWithAssertions(t, "{}", func(r *http.Request) {
					assert.Equal(t, "True", r.Header.Get("Metadata"))
				})
			},
		},
		{
			name:   "there aren't query parameters",
			params: map[string]string{},
			setupFunc: func(params map[string]string) *httptest.Server {
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
			setupFunc: func(params map[string]string) *httptest.Server {
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

	logger, _ := zap.NewDevelopment()
	for _, tt := range tests {
		imdsClient := &client{
			httpClient: internalhttp.NewClient(logger),
			logger:     logger,
		}
		imds := tt.setupFunc(tt.params)
		defer imds.Close()

		ctx := context.Background()

		err := imdsClient.callIMDS(ctx, imds.URL, tt.params, &VMInstanceData{})
		assert.NoError(t, err)
	}
}

func TestGetInstanceData(t *testing.T) {
	const (
		mockVMInstanceDataJSON = `{"compute":{"resourceId": "resourceId"}}`
		mockVMAttestedDataJSON = `{"signature":"signature"}`
		malformedJSON          = `{{}`
	)

	tests := []struct {
		name               string
		json               string
		expectedErrSubStr  string
		expectedResourceID string
	}{
		{
			name:               "should call the correct IMDS endpoint with the correct query parameters",
			json:               mockVMInstanceDataJSON,
			expectedErrSubStr:  "",
			expectedResourceID: "resourceId",
		},
		{
			name:               "unable parse instance data response from IMDS",
			json:               malformedJSON,
			expectedErrSubStr:  "failed to unmarshal IMDS data",
			expectedResourceID: "",
		},
	}

	logger, _ := zap.NewDevelopment()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			imds := mockIMDSWithAssertions(t, tt.json, func(r *http.Request) {
				assert.Equal(t, "/metadata/instance", r.URL.Path)
				queryParameters := r.URL.Query()
				assert.Equal(t, apiVersion, queryParameters.Get("api-version"))
				assert.Equal(t, "json", queryParameters.Get("format"))
			})
			defer imds.Close()

			imdsClient := &client{
				httpClient: internalhttp.NewClient(logger),
				logger:     logger,
				baseURL:    imds.URL,
			}

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			instanceData, err := imdsClient.GetInstanceData(ctx)

			if tt.expectedErrSubStr != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedErrSubStr)
				assert.Nil(t, instanceData)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, instanceData)
				assert.Equal(t, tt.expectedResourceID, instanceData.Compute.ResourceID)
			}
		})
	}
}

func TestGetAttestedData(t *testing.T) {
	const (
		mockVMAttestedDataJSON = `{"signature":"signature"}`
		malformedJSON          = `{{}`
	)

	tests := []struct {
		name              string
		json              string
		expectedErrSubStr string // Empty string indicates no error expected
		expectedSignature string // For validating the signature in the attested data
	}{
		{
			name:              "should call the correct IMDS endpoint with the correct query parameters",
			json:              mockVMAttestedDataJSON,
			expectedErrSubStr: "",
			expectedSignature: "signature",
		},
		{
			name:              "unable to parse attested data response from IMDS",
			json:              malformedJSON,
			expectedErrSubStr: "failed to unmarshal IMDS data",
			expectedSignature: "",
		},
	}

	logger, _ := zap.NewDevelopment()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			imds := mockIMDSWithAssertions(t, tt.json, func(r *http.Request) {
				assert.Equal(t, "/metadata/attested/document", r.URL.Path)
				queryParameters := r.URL.Query()
				assert.Equal(t, apiVersion, queryParameters.Get("api-version"))
				assert.Equal(t, "json", queryParameters.Get("format"))
				assert.Equal(t, "nonce", queryParameters.Get("nonce"))
			})
			defer imds.Close()

			imdsClient := &client{
				httpClient: internalhttp.NewClient(logger),
				logger:     logger,
				baseURL:    imds.URL,
			}

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			nonce := "nonce"
			attestedData, err := imdsClient.GetAttestedData(ctx, nonce)

			if tt.expectedErrSubStr != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedErrSubStr)
				assert.Nil(t, attestedData)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, attestedData)
				assert.Equal(t, tt.expectedSignature, attestedData.Signature)
			}
		})
	}
}

func mockIMDSWithAssertions(t *testing.T, response string, assertions func(r *http.Request)) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.True(t, strings.HasPrefix(r.Header.Get("User-Agent"), "aks-secure-tls-bootstrap-client/"))
		assertions(r)
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, response)
	}))
}
