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
	const (
		mockVMInstanceDataJSON = `{"compute":{"resourceId": "resourceId"}}`
		mockVMAttestedDataJSON = `{"signature":"signature"}`
		malformedJSON          = `{{}`
	)
	var (
		logger     *zap.Logger
		imdsClient *client
	)

	logger, _ = zap.NewDevelopment()

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
					assert.Equal(t, r.Header.Get("Metadata"), "True")
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
						assert.Equal(t, queryParameters.Get(param), expectedValue)
					}
				})

				return imds
			},
		},
	}

	for _, tt := range tests {
		imdsClient = &client{
			httpClient: internalhttp.NewClient(logger),
			logger:     logger,
		}
		imds := tt.setupFunc(tt.params)
		defer imds.Close()

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

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
	var (
		imdsClient *client
	)

	tests := []struct {
		name              string
		json              string
		instanceDataIsErr bool
		assertions        func(context.Context)
	}{
		{
			name:              "should call the correct IMDS endpoint with the correct query parameters",
			json:              mockVMInstanceDataJSON,
			instanceDataIsErr: false,
			assertions: func(ctx context.Context) {
				instanceData, err := imdsClient.GetInstanceData(ctx)
				assert.NoError(t, err)
				assert.NotNil(t, instanceData)
				assert.Equal(t, "resourceId", instanceData.Compute.ResourceID)
			},
		},
		{
			name:              "unable parse instance data response from IMDS",
			json:              malformedJSON,
			instanceDataIsErr: true,
			assertions: func(ctx context.Context) {
				instanceData, err := imdsClient.GetInstanceData(ctx)

				assert.Nil(t, instanceData)
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "failed to unmarshal IMDS data")
			},
		},
	}
	for _, tt := range tests {
		imds := mockIMDSWithAssertions(t, tt.json, func(r *http.Request) {
			assert.Equal(t, r.URL.Path, "/metadata/instance")
			queryParameters := r.URL.Query()
			assert.Equal(t, queryParameters.Get("api-version"), apiVersion)
			assert.Equal(t, queryParameters.Get("format"), "json")
		})
		defer imds.Close()
		imdsClient.baseURL = imds.URL

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		tt.assertions(ctx)
	}
}

func TestGetAttestedData(t *testing.T) {
	const (
		mockVMInstanceDataJSON = `{"compute":{"resourceId": "resourceId"}}`
		mockVMAttestedDataJSON = `{"signature":"signature"}`
		malformedJSON          = `{{}`
	)
	var (
		logger     *zap.Logger
		imdsClient *client
	)
	logger, _ = zap.NewDevelopment()
	tests := []struct {
		name       string
		json       string
		error      string
		assertions func(context.Context)
	}{
		{
			name:  "should call the correct IMDS endpoint with the correct query parameters",
			json:  mockVMAttestedDataJSON,
			error: "",
			assertions: func(ctx context.Context) {
				nonce := "nonce"
				attestedData, err := imdsClient.GetAttestedData(ctx, nonce)
				assert.NoError(t, err)
				assert.NotNil(t, attestedData)
				assert.Equal(t, "signature", attestedData.Signature)
			},
		},
		{
			name:  "unable to parse attested data response from IMDS",
			json:  malformedJSON,
			error: "failed to unmarshal IMDS data",
			assertions: func(ctx context.Context) {
				nonce := "nonce"
				attestedData, err := imdsClient.GetAttestedData(ctx, nonce)
				assert.Nil(t, attestedData)
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "failed to unmarshal IMDS data")
			},
		},
	}
	for _, tt := range tests {
		imds := mockIMDSWithAssertions(t, tt.json, func(r *http.Request) {
			assert.Equal(t, r.URL.Path, "/metadata/attested/document")
			queryParameters := r.URL.Query()
			assert.Equal(t, queryParameters.Get("api-version"), apiVersion)
			assert.Equal(t, queryParameters.Get("format"), "json")
			assert.Equal(t, queryParameters.Get("nonce"), "nonce")
		})
		defer imds.Close()
		imdsClient = &client{
			httpClient: internalhttp.NewClient(logger),
			logger:     logger,
			baseURL:    imds.URL,
		}

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		tt.assertions(ctx)
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
