// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package bootstrap

import (
	"context"
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

func TestGetToken(t *testing.T) {
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
				return func(ctx context.Context, token *adal.ServicePrincipalToken, isMSI bool) (string, error) {
					return "token", nil
				}
			},
			expectedToken: "",
			expectedErr:   errors.New(`getting azure environment config for cloud "invalid"`),
		},
		{
			name: "error generating a service principal access token with client secret due to missing client secret",
			setupCloudProviderConfig: func(t *testing.T, config *cloud.ProviderConfig) {
				config.CloudName = azure.PublicCloud.Name
				config.ClientID = "service-principal-id"
				config.ClientSecret = ""
			},
			setupExtractAccessTokenFunc: func(t *testing.T) extractAccessTokenFunc {
				return func(ctx context.Context, token *adal.ServicePrincipalToken, isMSI bool) (string, error) {
					return "token", nil
				}
			},
			expectedToken: "",
			expectedErr:   errors.New("generating service principal access token with client secret"),
		},
		{
			name: "error b64-decoding client secret certificate data",
			setupCloudProviderConfig: func(t *testing.T, config *cloud.ProviderConfig) {
				config.CloudName = azure.PublicCloud.Name
				config.ClientID = "service-principal-id"
				config.ClientSecret = "certificate:YW55IGNhcm5hbCBwbGVhc3U======" // invalid b64-encoding
			},
			setupExtractAccessTokenFunc: func(t *testing.T) extractAccessTokenFunc {
				return func(ctx context.Context, token *adal.ServicePrincipalToken, isMSI bool) (string, error) {
					return "token", nil
				}
			},
			expectedToken: "",
			expectedErr:   errors.New("b64-decoding certificate data in client secret"),
		},
		{
			name: "error pfx-decoding client secret certificate data",
			setupCloudProviderConfig: func(t *testing.T, config *cloud.ProviderConfig) {
				config.CloudName = azure.PublicCloud.Name
				config.ClientID = "service-principal-id"
				config.ClientSecret = "certificate:dGVzdAo=" // b64-encoding of "test"
			},
			setupExtractAccessTokenFunc: func(t *testing.T) extractAccessTokenFunc {
				return func(ctx context.Context, token *adal.ServicePrincipalToken, isMSI bool) (string, error) {
					return "token", nil
				}
			},
			expectedToken: "",
			expectedErr:   errors.New("decoding pfx certificate data in client secret"),
		},
		{
			name: "error generating service principal token with certificate data",
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
				return func(ctx context.Context, token *adal.ServicePrincipalToken, isMSI bool) (string, error) {
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
				return func(ctx context.Context, token *adal.ServicePrincipalToken, isMSI bool) (string, error) {
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
				return func(ctx context.Context, token *adal.ServicePrincipalToken, isMSI bool) (string, error) {
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
				return func(ctx context.Context, token *adal.ServicePrincipalToken, isMSI bool) (string, error) {
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
				return func(ctx context.Context, token *adal.ServicePrincipalToken, isMSI bool) (string, error) {
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
				return func(ctx context.Context, token *adal.ServicePrincipalToken, isMSI bool) (string, error) {
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
				return func(ctx context.Context, token *adal.ServicePrincipalToken, isMSI bool) (string, error) {
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
			cloudProviderConfig := &cloud.ProviderConfig{
				TenantID: testTenantID,
			}
			c.setupCloudProviderConfig(t, cloudProviderConfig)

			token, err := client.getToken(ctx, &Config{
				AADResource:            testResource,
				CloudProviderConfig:    cloudProviderConfig,
				UserAssignedIdentityID: c.customClientID,
			})
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

func TestIsTerminalGetTokenError(t *testing.T) {
	cases := []struct {
		name     string
		config   *Config
		err      error
		expected bool
	}{
		{
			name:     "context deadline exceeded is terminal",
			config:   &Config{},
			err:      context.DeadlineExceeded,
			expected: true,
		},
		{
			name:     "non token refresh error is terminal",
			config:   &Config{},
			err:      errors.New("invalid cloud config"),
			expected: true,
		},
		{
			name: "service principal bad request is terminal",
			config: &Config{
				CloudProviderConfig: &cloud.ProviderConfig{
					ClientID: "service-principal-id",
				},
			},
			err: &fakeTokenRefreshError{
				resp: &http.Response{StatusCode: http.StatusBadRequest},
				err:  errors.New(`adal: Refresh request failed. Status Code = '400'. Response body: {"error":"invalid_client"}`),
			},
			expected: true,
		},
		{
			name: "managed identity identity not found is retryable",
			config: &Config{
				CloudProviderConfig: &cloud.ProviderConfig{
					ClientID:               clientIDForMSI,
					UserAssignedIdentityID: "identity-id",
				},
			},
			err: &fakeTokenRefreshError{
				resp: &http.Response{StatusCode: http.StatusBadRequest},
				err:  errors.New(`adal: Refresh request failed. Status Code = '400'. Response body: {"error":"invalid_request","error_description":"Identity not found"}`),
			},
			expected: false,
		},
		{
			name: "managed identity not found response is retryable",
			config: &Config{
				UserAssignedIdentityID: "identity-id",
			},
			err: &fakeTokenRefreshError{
				resp: &http.Response{StatusCode: http.StatusNotFound},
				err:  errors.New("adal: retryable IMDS status"),
			},
			expected: false,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.expected, isTerminalGetTokenError(c.err, c.config))
		})
	}
}

func TestGetAccessToken(t *testing.T) {
	t.Run("retries managed identity identity not found errors", func(t *testing.T) {
		attempts := 0
		sleeps := 0
		client := &client{
			getTokenFunc: func(ctx context.Context, config *Config) (string, error) {
				attempts++
				if attempts < 3 {
					return "", &fakeTokenRefreshError{
						resp: &http.Response{StatusCode: http.StatusBadRequest},
						err:  errors.New(`adal: Refresh request failed. Status Code = '400'. Response body: {"error":"invalid_request","error_description":"Identity not found"}`),
					}
				}
				return "token", nil
			},
			sleepFunc: func(ctx context.Context, duration time.Duration) error {
				sleeps++
				assert.Equal(t, getAccessTokenRetryInterval, duration)
				return nil
			},
		}

		token, err := client.getAccessToken(telemetry.WithTracing(log.NewTestContext()), &Config{
			GetAccessTokenTimeout: time.Minute,
			CloudProviderConfig: &cloud.ProviderConfig{
				ClientID:               clientIDForMSI,
				UserAssignedIdentityID: "identity-id",
			},
		})
		assert.NoError(t, err)
		assert.Equal(t, "token", token)
		assert.Equal(t, 3, attempts)
		assert.Equal(t, 2, sleeps)
	})

	t.Run("does not retry terminal errors", func(t *testing.T) {
		attempts := 0
		client := &client{
			getTokenFunc: func(ctx context.Context, config *Config) (string, error) {
				attempts++
				return "", errors.New("invalid cloud config")
			},
			sleepFunc: func(ctx context.Context, duration time.Duration) error {
				t.Fatalf("sleep should not be called for terminal errors")
				return nil
			},
		}

		token, err := client.getAccessToken(telemetry.WithTracing(log.NewTestContext()), &Config{
			GetAccessTokenTimeout: time.Minute,
		})
		assert.Empty(t, token)
		assert.EqualError(t, err, "invalid cloud config")
		assert.Equal(t, 1, attempts)
	})

	t.Run("stops retrying when context deadline is exceeded", func(t *testing.T) {
		attempts := 0
		client := &client{
			getTokenFunc: func(ctx context.Context, config *Config) (string, error) {
				attempts++
				return "", &fakeTokenRefreshError{
					resp: &http.Response{StatusCode: http.StatusInternalServerError},
					err:  errors.New("temporary token service failure"),
				}
			},
			sleepFunc: func(ctx context.Context, duration time.Duration) error {
				<-ctx.Done()
				return ctx.Err()
			},
		}

		token, err := client.getAccessToken(telemetry.WithTracing(log.NewTestContext()), &Config{
			GetAccessTokenTimeout: 10 * time.Millisecond,
		})
		assert.Empty(t, token)
		assert.ErrorIs(t, err, context.DeadlineExceeded)
		assert.Equal(t, 1, attempts)
	})
}
