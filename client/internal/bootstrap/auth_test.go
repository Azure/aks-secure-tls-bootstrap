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
	var (
		logger       *zap.Logger
		testResource = "resource"
		testTenantID = "d87a2c3e-0c0c-42b2-a883-e48cd8723e22"
	)
	logger, _ = zap.NewDevelopment()
	tests := []struct {
		name        string
		customID    string
		setupClient func(*testing.T) (*Client, *cloud.ProviderConfig)
		expectErr   bool
		errSubstrs  []string
		expectToken string
	}{
		{
			name: "error generating MSI access token",
			setupClient: func(t *testing.T) (*Client, *cloud.ProviderConfig) {
				client := &Client{
					logger: logger,
					extractAccessTokenFunc: func(token *adal.ServicePrincipalToken) (string, error) {
						assert.NotNil(t, token)
						return "", errors.New("generating MSI access token")
					},
				}
				providerCfg := &cloud.ProviderConfig{
					UserAssignedIdentityID: "kubelet-identity-id",
					TenantID:               testTenantID,
				}

				return client, providerCfg
			},
			expectErr:   true,
			errSubstrs:  []string{"generating MSI access token"},
			expectToken: "",
		},
		{
			name: "error getting azure environment config for specified cloud",
			setupClient: func(t *testing.T) (*Client, *cloud.ProviderConfig) {
				client := &Client{
					logger: logger,
					extractAccessTokenFunc: func(token *adal.ServicePrincipalToken) (string, error) {
						return "", nil
					},
				}
				providerCfg := &cloud.ProviderConfig{
					CloudName:    "invalid",
					ClientID:     "service-principal-id",
					ClientSecret: "secret",
					TenantID:     testTenantID,
				}

				return client, providerCfg
			},
			expectErr:   true,
			errSubstrs:  []string{`getting azure environment config for cloud "invalid"`},
			expectToken: "",
		},
		{
			name: "service principal client secret contains certificate data",
			setupClient: func(t *testing.T) (*Client, *cloud.ProviderConfig) {
				certData, err := testutil.GenerateCertAndKeyAsEncodedPFXData(testutil.CertTemplate{
					CommonName:   "aad",
					Organization: "azure",
					Expiration:   time.Now().Add(time.Hour),
				})
				assert.NoError(t, err)
				client := &Client{
					logger: logger,
					extractAccessTokenFunc: func(token *adal.ServicePrincipalToken) (string, error) {
						assert.NotNil(t, token)
						return "token", nil
					},
					// certData: certData,
				}
				providerCfg := &cloud.ProviderConfig{
					CloudName:    azure.PublicCloud.Name,
					ClientID:     "service-principal-id",
					ClientSecret: "certificate:" + certData,
					TenantID:     testTenantID,
				}

				return client, providerCfg
			},
			expectErr:   false,
			errSubstrs:  nil,
			expectToken: "token",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, providerCfg := tt.setupClient(t)
			token, err := client.getAccessToken(tt.customID, testResource, providerCfg)

			if tt.expectErr {
				assert.Error(t, err)
				for _, substr := range tt.errSubstrs {
					assert.Contains(t, err.Error(), substr)
				}
				assert.Empty(t, token)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectToken, token)
			}
		})
	}
}
