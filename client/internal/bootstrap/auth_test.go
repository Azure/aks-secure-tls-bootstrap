// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package bootstrap

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"

	"github.com/Azure/aks-secure-tls-bootstrap/client/internal/cloud"
	"github.com/Azure/aks-secure-tls-bootstrap/client/internal/testutil"
	"github.com/Azure/go-autorest/autorest/adal"
	"github.com/Azure/go-autorest/autorest/azure"
)

func TestGetAuthToken(t *testing.T) {
	var testTenantID = "d87a2c3e-0c0c-42b2-a883-e48cd8723e22"
	tests := []struct {
		name        string
		customID    string
		setupClient func(*testing.T, *Client) *cloud.ProviderConfig
		clientStr   string
		errSubstrs  []string
		expectToken string
		expectErr   error
	}{
		{
			name: "error generating MSI access token",
			setupClient: func(t *testing.T, client *Client) *cloud.ProviderConfig {
				providerCfg := &cloud.ProviderConfig{
					UserAssignedIdentityID: "kubelet-identity-id",
					TenantID:               testTenantID,
				}

				return providerCfg
			},
			clientStr:   "",
			errSubstrs:  []string{"generating MSI access token"},
			expectToken: "",
			expectErr:   errors.New("generating MSI access token"),
		},
		{
			name: "error getting azure environment config for specified cloud",
			setupClient: func(t *testing.T, client *Client) *cloud.ProviderConfig {
				providerCfg := &cloud.ProviderConfig{
					CloudName:    "invalid",
					ClientID:     "service-principal-id",
					ClientSecret: "secret",
					TenantID:     testTenantID,
				}

				return providerCfg
			},
			clientStr:   "",
			errSubstrs:  []string{`getting azure environment config for cloud "invalid"`},
			expectToken: "",
			expectErr:   errors.New(`getting azure environment config for cloud "invalid"`),
		},
		{
			name: "there is an error generating a service principal access token with username and password",
			setupClient: func(t *testing.T, client *Client) *cloud.ProviderConfig {
				providerCfg := &cloud.ProviderConfig{
					CloudName:    azure.PublicCloud.Name,
					ClientID:     "service-principal-id",
					ClientSecret: "", // empty secret to force a failure
					TenantID:     testTenantID,
				}
				return providerCfg
			},
			clientStr:   "",
			errSubstrs:  []string{"generating SPN access token with username and password"},
			expectToken: "",
			expectErr:   errors.New("generating SPN access token with username and password"),
		},
		{
			name: "there is an error b64-decoding the certificate data",
			setupClient: func(t *testing.T, client *Client) *cloud.ProviderConfig {
				providerCfg := &cloud.ProviderConfig{
					CloudName:    azure.PublicCloud.Name,
					ClientID:     "service-principal-id",
					ClientSecret: "certificate:YW55IGNhcm5hbCBwbGVhc3U======", // invalid b64-encoding
					TenantID:     testTenantID,
				}
				return providerCfg
			},
			clientStr:   "",
			errSubstrs:  []string{"b64-decoding certificate data in client secret"},
			expectToken: "",
			expectErr:   errors.New("b64-decoding certificate data in client secret"),
		},
		{
			name: "there is an error decoding the pfx certificate data",
			setupClient: func(t *testing.T, client *Client) *cloud.ProviderConfig {
				providerCfg := &cloud.ProviderConfig{
					CloudName:    azure.PublicCloud.Name,
					ClientID:     "service-principal-id",
					ClientSecret: "certificate:dGVzdAo=", // b64-encoding of "test"
					TenantID:     testTenantID,
				}
				return providerCfg
			},
			clientStr:   "",
			errSubstrs:  []string{"decoding pfx certificate data in client secret"},
			expectToken: "",
			expectErr:   errors.New("decoding pfx certificate data in client secret"),
		},
		{
			name: "there is an error generating a service principal token with certificate data",
			setupClient: func(t *testing.T, client *Client) *cloud.ProviderConfig {
				certData, err := testutil.GenerateCertAndKeyAsEncodedPFXData(testutil.CertTemplate{
					CommonName:   "aad",
					Organization: "azure",
					Expiration:   time.Now().Add(time.Hour),
				})
				assert.NoError(t, err)

				providerCfg := &cloud.ProviderConfig{
					CloudName:    azure.PublicCloud.Name,
					ClientID:     "service-principal-id",
					ClientSecret: "certificate:" + certData,
					TenantID:     testTenantID,
				}

				return providerCfg
			},
			clientStr:   "",
			errSubstrs:  []string{"generating SPN access token with certificate"},
			expectToken: "",
			expectErr:   errors.New("generating SPN access token with certificate"),
		},
		{
			name: "UserAssignedIdentityID is specified in cloud provider config",
			setupClient: func(t *testing.T, client *Client) *cloud.ProviderConfig {
				providerCfg := &cloud.ProviderConfig{
					UserAssignedIdentityID: "kubelet-identity-id",
					TenantID:               testTenantID,
				}
				return providerCfg
			},
			clientStr:   "token",
			errSubstrs:  nil,
			expectToken: "token",
			expectErr:   nil,
		},
		{
			name:     "a custom client ID is specified",
			customID: "custom",
			setupClient: func(t *testing.T, client *Client) *cloud.ProviderConfig {
				providerCfg := &cloud.ProviderConfig{
					UserAssignedIdentityID: "kubelet-identity-id",
					TenantID:               testTenantID,
				}
				return providerCfg
			},
			clientStr:   "token",
			errSubstrs:  nil,
			expectToken: "token",
			expectErr:   nil,
		},
		{
			name: "service principal client secret does not contain certificate data",
			setupClient: func(t *testing.T, client *Client) *cloud.ProviderConfig {
				cloudProviderConfig := &cloud.ProviderConfig{
					CloudName:    azure.PublicCloud.Name,
					ClientID:     "service-principal-id",
					ClientSecret: "secret",
					TenantID:     testTenantID,
				}
				return cloudProviderConfig
			},
			clientStr:   "token",
			errSubstrs:  nil,
			expectToken: "token",
			expectErr:   nil,
		},
		{
			name: "service principal client secret contains certificate data",
			setupClient: func(t *testing.T, client *Client) *cloud.ProviderConfig {
				certData, err := testutil.GenerateCertAndKeyAsEncodedPFXData(testutil.CertTemplate{
					CommonName:   "aad",
					Organization: "azure",
					Expiration:   time.Now().Add(time.Hour),
				})
				assert.NoError(t, err)

				providerCfg := &cloud.ProviderConfig{
					CloudName:    azure.PublicCloud.Name,
					ClientID:     "service-principal-id",
					ClientSecret: "certificate:" + certData,
					TenantID:     testTenantID,
				}

				return providerCfg
			},
			clientStr:   "token",
			errSubstrs:  nil,
			expectToken: "token",
			expectErr:   nil,
		},
	}

	var testResource = "resource"
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger, _ := zap.NewDevelopment()
			client := &Client{
				logger: logger,
				extractAccessTokenFunc: func(token *adal.ServicePrincipalToken) (string, error) {
					return tt.clientStr, tt.expectErr
				},
			}
			providerCfg := tt.setupClient(t, client)
			token, err := client.getAccessToken(tt.customID, testResource, providerCfg)

			if len(tt.errSubstrs) > 0 {
				assert.Error(t, err)
				for _, substr := range tt.errSubstrs {
					assert.ErrorContains(t, err, substr)
				}
				assert.Empty(t, token)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectToken, token)
			}
		})
	}
}
