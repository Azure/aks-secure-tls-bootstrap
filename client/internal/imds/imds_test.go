// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package imds

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	internalhttp "github.com/Azure/aks-secure-tls-bootstrap/client/internal/http"
	"github.com/Azure/aks-secure-tls-bootstrap/client/internal/log"
	"github.com/stretchr/testify/assert"
)

func TestParseErrorDescription(t *testing.T) {
	cases := []struct {
		name                string
		resp                *http.Response
		expectedDescription string
		expectedErr         error
	}{
		{
			name:                "response is nil",
			resp:                nil,
			expectedDescription: "",
			expectedErr:         nil,
		},
		{
			name: "response body is malformed",
			resp: &http.Response{
				Body: io.NopCloser(strings.NewReader("malformed")),
			},
			expectedDescription: "",
			expectedErr:         errors.New("unmarshalling IMDS error resposne"),
		},
		{
			name: "response body does not contain error_description",
			resp: &http.Response{
				StatusCode: http.StatusBadRequest,
				Body:       io.NopCloser(strings.NewReader(`{"error":"invalid_request"}`)),
			},
			expectedDescription: "",
			expectedErr:         nil,
		},
		{
			name: "response body contains an error_description",
			resp: &http.Response{
				StatusCode: http.StatusBadRequest,
				Body:       io.NopCloser(strings.NewReader(`{"error":"invalid_request","error_description":"Identity not found"}`)),
			},
			expectedDescription: "Identity not found",
			expectedErr:         nil,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			description, err := ParseErrorDescription(c.resp)
			if c.expectedErr != nil {
				assert.ErrorContains(t, err, c.expectedErr.Error())
			} else {
				assert.Nil(t, err)
			}
			assert.Equal(t, c.expectedDescription, description)
		})
	}
}

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
	const (
		mockVMInstanceDataJSON = `{"compute":{"resourceId": "resourceId"}}`
		malformedJSON          = `{{}`
	)

	cases := []struct {
		name               string
		json               string
		expectedErr        string
		expectedResourceID string
	}{
		{
			name:               "should call the correct IMDS endpoint with the correct query parameters",
			json:               mockVMInstanceDataJSON,
			expectedErr:        "",
			expectedResourceID: "resourceId",
		},
		{
			name:               "unable parse instance data response from IMDS",
			json:               malformedJSON,
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
	const (
		mockVMAttestedDataJSON = `{"signature":"signature"}`
		malformedJSON          = `{{}`
	)

	cases := []struct {
		name              string
		json              string
		expectedErr       string // Empty string indicates no error expected
		expectedSignature string // For validating the signature in the attested data
	}{
		{
			name:              "should call the correct IMDS endpoint with the correct query parameters",
			json:              mockVMAttestedDataJSON,
			expectedErr:       "",
			expectedSignature: "signature",
		},
		{
			name:              "unable to parse attested data response from IMDS",
			json:              malformedJSON,
			expectedErr:       "failed to unmarshal IMDS data",
			expectedSignature: "",
		},
	}

	ctx := log.NewTestContext()

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			imds := mockIMDSWithAssertions(t, c.json, func(r *http.Request) {
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
		fmt.Fprintln(w, response)
	}))
}
