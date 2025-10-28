// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package bootstrap

import (
	"encoding/base64"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/Azure/aks-secure-tls-bootstrap/client/internal/cloud"
	"github.com/Azure/aks-secure-tls-bootstrap/client/internal/log"
	"github.com/Azure/aks-secure-tls-bootstrap/client/internal/telemetry"
	"github.com/Azure/aks-secure-tls-bootstrap/client/internal/testutil"
	"github.com/Azure/go-autorest/autorest/adal"
	"github.com/Azure/go-autorest/autorest/azure"
)

func TestGetAccessToken(t *testing.T) {
	cases := []struct {
		name                        string
		customClientID              string
		setupCloudProviderConfig    func(t *testing.T, config *cloud.ProviderConfig)
		setupExtractAccessTokenFunc func(t *testing.T) extractAccessTokenFunc
		expectedToken               string
		expectedErr                 error
	}{
		{
			name: "error getting azure environment config for specified cloud",
			setupCloudProviderConfig: func(t *testing.T, config *cloud.ProviderConfig) {
				config.CloudName = "invalid"
				config.ClientID = "service-principal-id"
				config.ClientSecret = "secret"
			},
			setupExtractAccessTokenFunc: func(t *testing.T) extractAccessTokenFunc {
				return func(token *adal.ServicePrincipalToken, isMSI bool) (string, error) {
					return "token", nil
				}
			},
			expectedToken: "",
			expectedErr:   errors.New(`getting azure environment config for cloud "invalid"`),
		},
		{
			name: "there is an error generating a service principal access token with client secret due to missing client secret",
			setupCloudProviderConfig: func(t *testing.T, config *cloud.ProviderConfig) {
				config.CloudName = azure.PublicCloud.Name
				config.ClientID = "service-principal-id"
				config.ClientSecret = ""
			},
			setupExtractAccessTokenFunc: func(t *testing.T) extractAccessTokenFunc {
				return func(token *adal.ServicePrincipalToken, isMSI bool) (string, error) {
					return "token", nil
				}
			},
			expectedToken: "",
			expectedErr:   errors.New("generating service principal access token with client secret"),
		},
		{
			name: "there is an error b64-decoding the client secret certificate data",
			setupCloudProviderConfig: func(t *testing.T, config *cloud.ProviderConfig) {
				config.CloudName = azure.PublicCloud.Name
				config.ClientID = "service-principal-id"
				config.ClientSecret = "certificate:YW55IGNhcm5hbCBwbGVhc3U======" // invalid b64-encoding
			},
			setupExtractAccessTokenFunc: func(t *testing.T) extractAccessTokenFunc {
				return func(token *adal.ServicePrincipalToken, isMSI bool) (string, error) {
					return "token", nil
				}
			},
			expectedToken: "",
			expectedErr:   errors.New("b64-decoding certificate data in client secret"),
		},
		{
			name: "there is an error decoding the client secret certificate data",
			setupCloudProviderConfig: func(t *testing.T, config *cloud.ProviderConfig) {
				config.CloudName = azure.PublicCloud.Name
				config.ClientID = "service-principal-id"
				config.ClientSecret = "certificate:dGVzdAo=" // b64-encoding of "test"
			},
			setupExtractAccessTokenFunc: func(t *testing.T) extractAccessTokenFunc {
				return func(token *adal.ServicePrincipalToken, isMSI bool) (string, error) {
					return "token", nil
				}
			},
			expectedToken: "",
			expectedErr:   errors.New("decoding pfx certificate data in client secret"),
		},
		{
			name: "there is an error generating a service principal token with certificate data",
			setupCloudProviderConfig: func(t *testing.T, config *cloud.ProviderConfig) {
				certData, err := testutil.GenerateCertAndKeyAsEncodedPFXData(testutil.CertTemplate{
					CommonName:   "aad",
					Organization: "azure",
					Expiration:   time.Now().Add(time.Hour),
				})
				assert.NoError(t, err)

				config.CloudName = azure.PublicCloud.Name
				config.ClientID = "service-principal-id"
				config.ClientSecret = "certificate:" + certData
			},
			setupExtractAccessTokenFunc: func(t *testing.T) extractAccessTokenFunc {
				return func(token *adal.ServicePrincipalToken, isMSI bool) (string, error) {
					return "", errors.New("generating service principal access token with certificate")
				}
			},
			expectedToken: "",
			expectedErr:   errors.New("generating service principal access token with certificate"),
		},
		{
			name: "UserAssignedIdentityID is specified in cloud provider config",
			setupCloudProviderConfig: func(t *testing.T, config *cloud.ProviderConfig) {
				config.UserAssignedIdentityID = "kubelet-identity-id"
				config.ClientID = clientIDForMSI
			},
			setupExtractAccessTokenFunc: func(t *testing.T) extractAccessTokenFunc {
				return func(token *adal.ServicePrincipalToken, isMSI bool) (string, error) {
					assert.Equal(t, maxMSIRefreshAttempts, token.MaxMSIRefreshAttempts)
					return "token", nil
				}
			},
			expectedToken: "token",
			expectedErr:   nil,
		},
		{
			name: "UserAssignedIdentityID is not specified in cloud provider config, but client ID indicates MSI usage",
			setupCloudProviderConfig: func(t *testing.T, config *cloud.ProviderConfig) {
				config.UserAssignedIdentityID = ""
				config.ClientID = clientIDForMSI
			},
			setupExtractAccessTokenFunc: func(t *testing.T) extractAccessTokenFunc {
				return func(token *adal.ServicePrincipalToken, isMSI bool) (string, error) {
					return "token", nil
				}
			},
			expectedToken: "",
			expectedErr:   errors.New("client ID within cloud provider config indicates usage of a managed identity, though no user-assigned identity ID was provided"),
		},
		{
			name:           "a custom client ID is specified",
			customClientID: "custom",
			setupCloudProviderConfig: func(t *testing.T, config *cloud.ProviderConfig) {
				config.UserAssignedIdentityID = "kubelet-identity-id"
				config.ClientID = clientIDForMSI
			},
			setupExtractAccessTokenFunc: func(t *testing.T) extractAccessTokenFunc {
				return func(token *adal.ServicePrincipalToken, isMSI bool) (string, error) {
					assert.Equal(t, maxMSIRefreshAttempts, token.MaxMSIRefreshAttempts)
					return "token", nil
				}
			},
			expectedToken: "token",
			expectedErr:   nil,
		},
		{
			name: "service principal client secret does not contain certificate data",
			setupCloudProviderConfig: func(t *testing.T, config *cloud.ProviderConfig) {
				config.CloudName = azure.PublicCloud.Name
				config.ClientID = "service-principal-id"
				config.ClientSecret = "secret"
			},
			setupExtractAccessTokenFunc: func(t *testing.T) extractAccessTokenFunc {
				return func(token *adal.ServicePrincipalToken, isMSI bool) (string, error) {
					return "token", nil
				}
			},
			expectedToken: "token",
			expectedErr:   nil,
		},
		{
			name: "service principal client secret contains certificate data",
			setupCloudProviderConfig: func(t *testing.T, config *cloud.ProviderConfig) {
				certData, err := testutil.GenerateCertAndKeyAsEncodedPFXData(testutil.CertTemplate{
					CommonName:   "aad",
					Organization: "azure",
					Expiration:   time.Now().Add(time.Hour),
				})
				assert.NoError(t, err)

				config.CloudName = azure.PublicCloud.Name
				config.ClientID = "service-principal-id"
				config.ClientSecret = "certificate:" + certData
			},
			setupExtractAccessTokenFunc: func(t *testing.T) extractAccessTokenFunc {
				return func(token *adal.ServicePrincipalToken, isMSI bool) (string, error) {
					return "token", nil
				}
			},
			expectedToken: "token",
			expectedErr:   nil,
		},
		{
			name: "service principal client secret is b64-decoded and contains certificate data",
			setupCloudProviderConfig: func(t *testing.T, config *cloud.ProviderConfig) {
				certData, err := testutil.GenerateCertAndKeyAsEncodedPFXData(testutil.CertTemplate{
					CommonName:   "aad",
					Organization: "azure",
					Expiration:   time.Now().Add(time.Hour),
				})
				assert.NoError(t, err)

				config.CloudName = azure.PublicCloud.Name
				config.ClientID = "service-principal-id"
				config.ClientSecret = base64.StdEncoding.EncodeToString([]byte("certificate:" + certData))
			},
			setupExtractAccessTokenFunc: func(t *testing.T) extractAccessTokenFunc {
				return func(token *adal.ServicePrincipalToken, isMSI bool) (string, error) {
					return "token", nil
				}
			},
			expectedToken: "token",
			expectedErr:   nil,
		},
	}

	testTenantID := "d87a2c3e-0c0c-42b2-a883-e48cd8723e22"
	testResource := "resource"

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ctx := telemetry.WithTracing(log.NewTestContext())
			client := &client{
				extractAccessTokenFunc: c.setupExtractAccessTokenFunc(t),
			}
			providerCfg := &cloud.ProviderConfig{
				TenantID: testTenantID,
			}
			c.setupCloudProviderConfig(t, providerCfg)

			token, err := client.getAccessToken(ctx, c.customClientID, testResource, providerCfg)
			if c.expectedErr != nil {
				assert.Error(t, err)
				assert.ErrorContains(t, err, c.expectedErr.Error())
				assert.Empty(t, token)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, c.expectedToken, token)
			}
		})
	}
}

func TestTokenRefreshErrorToGetAccessTokenFailure(t *testing.T) {
	cases := []struct {
		name        string
		err         error
		isMSI       bool
		expectedErr *bootstrapError
	}{
		{
			name: "error is not an adal.TokenRefreshError",
			err:  errors.New("unexpected error"),
			expectedErr: &bootstrapError{
				errorType: ErrorTypeGetAccessTokenFailure,
				retryable: true,
				inner:     errors.New("obtaining fresh access token: unexpected error"),
			},
		},
		{
			name: "error is an adal.TokenRefreshError with nil response",
			err: &fakeRefreshError{
				resp: nil,
				err:  errors.New("refresh error"),
			},
			expectedErr: &bootstrapError{
				errorType: ErrorTypeGetAccessTokenFailure,
				retryable: true,
				inner:     errors.New("obtaining fresh access token: refresh error"),
			},
		},
		{
			name:  "error is an adal.TokenRefreshError with 5XX response for MSI",
			isMSI: true,
			err: &fakeRefreshError{
				resp: &http.Response{
					StatusCode: http.StatusInternalServerError,
				},
				err: errors.New("refresh error"),
			},
			expectedErr: &bootstrapError{
				errorType: ErrorTypeGetAccessTokenFailure,
				retryable: true,
				inner:     errors.New("obtaining fresh access token: refresh error"),
			},
		},
		{
			name: "error is an adal.TokenRefreshError with 5XX response for service principal",
			err: &fakeRefreshError{
				resp: &http.Response{
					StatusCode: http.StatusInternalServerError,
				},
				err: errors.New("refresh error"),
			},
			expectedErr: &bootstrapError{
				errorType: ErrorTypeGetAccessTokenFailure,
				retryable: true,
				inner:     errors.New("obtaining fresh access token: refresh error"),
			},
		},
		{
			name:  "error is an adal.TokenRefreshError with 429 response for MSI",
			isMSI: true,
			err: &fakeRefreshError{
				resp: &http.Response{
					StatusCode: http.StatusTooManyRequests,
				},
				err: errors.New("refresh error"),
			},
			expectedErr: &bootstrapError{
				errorType: ErrorTypeGetAccessTokenFailure,
				retryable: true,
				inner:     errors.New("obtaining fresh access token: refresh error"),
			},
		},
		{
			name: "error is an adal.TokenRefreshError with 429 response for service principal",
			err: &fakeRefreshError{
				resp: &http.Response{
					StatusCode: http.StatusTooManyRequests,
				},
				err: errors.New("refresh error"),
			},
			expectedErr: &bootstrapError{
				errorType: ErrorTypeGetAccessTokenFailure,
				retryable: false,
				inner:     errors.New("obtaining fresh access token: refresh error"),
			},
		},
		{
			name:  "error is an adal.TokenRefreshError with 404 response for MSI",
			isMSI: true,
			err: &fakeRefreshError{
				resp: &http.Response{
					StatusCode: http.StatusNotFound,
				},
				err: errors.New("refresh error"),
			},
			expectedErr: &bootstrapError{
				errorType: ErrorTypeGetAccessTokenFailure,
				retryable: true,
				inner:     errors.New("obtaining fresh access token: refresh error"),
			},
		},
		{
			name: "error is an adal.TokenRefreshError with 404 response for service principal",
			err: &fakeRefreshError{
				resp: &http.Response{
					StatusCode: http.StatusNotFound,
				},
				err: errors.New("refresh error"),
			},
			expectedErr: &bootstrapError{
				errorType: ErrorTypeGetAccessTokenFailure,
				retryable: false,
				inner:     errors.New("obtaining fresh access token: refresh error"),
			},
		},
		{
			name:  "error is an adal.TokenRefreshError with an unknown 400 response for MSI",
			isMSI: true,
			err: &fakeRefreshError{
				resp: &http.Response{
					StatusCode: http.StatusBadRequest,
				},
				err: errors.New(`Refresh request failed. Status Code = '400'. Response body: {\"error\":\"invalid_request\"} Endpoint http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&client_id=id&resource=res`),
			},
			expectedErr: &bootstrapError{
				errorType: ErrorTypeGetAccessTokenFailure,
				retryable: false,
				inner:     errors.New(`obtaining fresh access token: Refresh request failed. Status Code = '400'. Response body: {\"error\":\"invalid_request\"} Endpoint http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&client_id=id&resource=res`),
			},
		},
		{
			name:  "error is an adal.TokenRefreshError with a non-retryable 400 response",
			isMSI: true,
			err: &fakeRefreshError{
				resp: &http.Response{
					StatusCode: http.StatusBadRequest,
				},
				err: errors.New(`Refresh request failed. Status Code = '400'. Response body: {\"error\":\"invalid_request\",\"error_description\":\"Bad request\"} Endpoint http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&client_id=id&resource=res`),
			},
			expectedErr: &bootstrapError{
				errorType: ErrorTypeGetAccessTokenFailure,
				retryable: false,
				inner:     errors.New(`obtaining fresh access token: Refresh request failed. Status Code = '400'. Response body: {\"error\":\"invalid_request\",\"error_description\":\"Bad request\"} Endpoint http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&client_id=id&resource=res`),
			},
		},
		{
			name:  "error is an adal.TokenRefreshError with a retryable 400 response",
			isMSI: true,
			err: &fakeRefreshError{
				resp: &http.Response{
					StatusCode: http.StatusBadRequest,
				},
				err: errors.New(`Refresh request failed. Status Code = '400'. Response body: {\"error\":\"invalid_request\",\"error_description\":\"Identity not found\"} Endpoint http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&client_id=id&resource=res`),
			},
			expectedErr: &bootstrapError{
				errorType: ErrorTypeGetAccessTokenFailure,
				retryable: true,
				inner:     errors.New(`obtaining fresh access token: Refresh request failed. Status Code = '400'. Response body: {\"error\":\"invalid_request\",\"error_description\":\"Identity not found\"} Endpoint http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&client_id=id&resource=res`),
			},
		},
		{
			name:  "error is an adal.TokenRefreshError with non-retryable response for MSI",
			isMSI: true,
			err: &fakeRefreshError{
				resp: &http.Response{
					StatusCode: http.StatusUnauthorized,
				},
				err: errors.New("unauthorized"),
			},
			expectedErr: &bootstrapError{
				errorType: ErrorTypeGetAccessTokenFailure,
				retryable: false,
				inner:     errors.New("obtaining fresh access token: unauthorized"),
			},
		},
		{
			name: "error is an adal.TokenRefreshError with non-retryable response for service principal",
			err: &fakeRefreshError{
				resp: &http.Response{
					StatusCode: http.StatusUnauthorized,
				},
				err: errors.New("unauthorized"),
			},
			expectedErr: &bootstrapError{
				errorType: ErrorTypeGetAccessTokenFailure,
				retryable: false,
				inner:     errors.New("obtaining fresh access token: unauthorized"),
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := tokenRefreshErrorToGetAccessTokenFailure(c.err, c.isMSI)
			var bootstrapErr *bootstrapError
			assert.True(t, errors.As(err, &bootstrapErr))
			assert.Equal(t, c.expectedErr.errorType, bootstrapErr.errorType)
			assert.Equal(t, c.expectedErr.retryable, bootstrapErr.retryable)
			assert.EqualError(t, c.expectedErr.inner, bootstrapErr.inner.Error())
		})
	}
}
