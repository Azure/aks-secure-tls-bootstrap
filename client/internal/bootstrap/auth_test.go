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
		name                     string
		customClientID           string
		setupCloudProviderConfig func(*testing.T, *cloud.ProviderConfig)
		expectToken              string
		expectErr                error
	}{
		{
			name:           "error generating MSI access token",
			customClientID: "",
			setupCloudProviderConfig: func(t *testing.T, config *cloud.ProviderConfig) {
				config.UserAssignedIdentityID = "kubelet-identity-id"
			},
			expectToken: "",
			expectErr:   errors.New("generating MSI access token"),
		},
		{
			name:           "error getting azure environment config for specified cloud",
			customClientID: "",
			setupCloudProviderConfig: func(t *testing.T, config *cloud.ProviderConfig) {
				config.CloudName = "invalid"
				config.ClientID = "service-principal-id"
				config.ClientSecret = "secret"
			},
			expectToken: "",
			expectErr:   errors.New(`getting azure environment config for cloud "invalid"`),
		},
		{
			name:           "there is an error generating a service principal access token with username and password",
			customClientID: "",
			setupCloudProviderConfig: func(t *testing.T, config *cloud.ProviderConfig) {
				config.CloudName = azure.PublicCloud.Name
				config.ClientID = "service-principal-id"
				config.ClientSecret = ""
			},
			expectToken: "",
			expectErr:   errors.New("generating SPN access token with username and password"),
		},
		{
			name:           "there is an error b64-decoding the certificate data",
			customClientID: "",
			setupCloudProviderConfig: func(t *testing.T, config *cloud.ProviderConfig) {
				config.CloudName = azure.PublicCloud.Name
				config.ClientID = "service-principal-id"
				config.ClientSecret = "certificate:YW55IGNhcm5hbCBwbGVhc3U======" // invalid b64-encoding
			},
			expectToken: "",
			expectErr:   errors.New("b64-decoding certificate data in client secret"),
		},
		{
			name:           "there is an error decoding the pfx certificate data",
			customClientID: "",
			setupCloudProviderConfig: func(t *testing.T, config *cloud.ProviderConfig) {
				config.CloudName = azure.PublicCloud.Name
				config.ClientID = "service-principal-id"
				config.ClientSecret = "certificate:dGVzdAo=" // b64-encoding of "test"
			},
			expectToken: "",
			expectErr:   errors.New("decoding pfx certificate data in client secret"),
		},
		{
			name:           "there is an error generating a service principal token with certificate data",
			customClientID: "",
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
			expectToken: "",
			expectErr:   errors.New("generating SPN access token with certificate"),
		},
		{
			name:           "UserAssignedIdentityID is specified in cloud provider config",
			customClientID: "",
			setupCloudProviderConfig: func(t *testing.T, config *cloud.ProviderConfig) {
				config.UserAssignedIdentityID = "kubelet-identity-id"
			},
			expectToken: "token",
			expectErr:   nil,
		},
		{
			name:           "a custom client ID is specified",
			customClientID: "custom",
			setupCloudProviderConfig: func(t *testing.T, config *cloud.ProviderConfig) {
				config.UserAssignedIdentityID = "kubelet-identity-id"
			},
			expectToken: "token",
			expectErr:   nil,
		},
		{
			name:           "service principal client secret does not contain certificate data",
			customClientID: "",
			setupCloudProviderConfig: func(t *testing.T, config *cloud.ProviderConfig) {
				config.CloudName = azure.PublicCloud.Name
				config.ClientID = "service-principal-id"
				config.ClientSecret = "secret"
			},
			expectToken: "token",
			expectErr:   nil,
		},
		{
			name:           "service principal client secret contains certificate data",
			customClientID: "",
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
					return tt.expectToken, tt.expectErr
				},
			}
			providerCfg := &cloud.ProviderConfig{
				TenantID: testTenantID,
			}
			tt.setupCloudProviderConfig(t, providerCfg)
			token, err := client.getAccessToken(tt.customClientID, testResource, providerCfg)

			if tt.expectErr != nil {
				assert.Error(t, err)
				assert.ErrorContains(t, err, tt.expectErr.Error())
				assert.Empty(t, token)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectToken, token)
			}
		})
	}
}
