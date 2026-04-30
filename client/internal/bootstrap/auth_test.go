// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package bootstrap

import (
	"context"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/Azure/aks-secure-tls-bootstrap/client/internal/cloud"
	"github.com/Azure/aks-secure-tls-bootstrap/client/internal/log"
	"github.com/Azure/aks-secure-tls-bootstrap/client/internal/testutil"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/fake"
	"github.com/Azure/go-autorest/autorest/azure"
)

func TestGetToken(t *testing.T) {
	cases := []struct {
		name                   string
		customClientID         string
		setCloudProviderConfig func(t *testing.T, config *cloud.ProviderConfig)
		// getTokenCredentialFunc is an override for cases that need to
		// control GetToken behavior. When nil, the default getTokenCredentialFunc is used (which
		// exercises real credential-creation logic, including any error paths).
		getTokenCredentialFunc getTokenCredentialFunc
		expectedToken          string
		expectedErr            error
	}{
		{
			name: "error getting azure environment config for specified cloud",
			setCloudProviderConfig: func(t *testing.T, config *cloud.ProviderConfig) {
				config.CloudName = "invalid"
				config.ClientID = "service-principal-id"
				config.ClientSecret = "secret"
			},
			expectedToken: "",
			expectedErr:   errors.New(`getting azure environment config for cloud "invalid"`),
		},
		{
			name: "error generating a service principal access token with client secret due to missing client secret",
			setCloudProviderConfig: func(t *testing.T, config *cloud.ProviderConfig) {
				config.CloudName = azure.PublicCloud.Name
				config.ClientID = "service-principal-id"
				config.ClientSecret = ""
			},
			expectedToken: "",
			expectedErr:   errors.New("generating service principal access token with client secret"),
		},
		{
			name: "error b64-decoding client secret certificate data",
			setCloudProviderConfig: func(t *testing.T, config *cloud.ProviderConfig) {
				config.CloudName = azure.PublicCloud.Name
				config.ClientID = "service-principal-id"
				config.ClientSecret = "certificate:YW55IGNhcm5hbCBwbGVhc3U======" // invalid b64-encoding
			},
			expectedToken: "",
			expectedErr:   errors.New("b64-decoding certificate data in client secret"),
		},
		{
			name: "error pfx-decoding client secret certificate data",
			setCloudProviderConfig: func(t *testing.T, config *cloud.ProviderConfig) {
				config.CloudName = azure.PublicCloud.Name
				config.ClientID = "service-principal-id"
				config.ClientSecret = "certificate:dGVzdAo=" // b64-encoding of "test"
			},
			expectedToken: "",
			expectedErr:   errors.New("decoding pfx certificate data in client secret"),
		},
		{
			name: "error returned from GetToken",
			setCloudProviderConfig: func(t *testing.T, config *cloud.ProviderConfig) {
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
			getTokenCredentialFunc: func(_ context.Context, _ *Config) (azcore.TokenCredential, error) {
				fakeCred := &fake.TokenCredential{}
				fakeCred.SetError(errors.New("generating service principal access token with certificate"))
				return fakeCred, nil
			},
			expectedToken: "",
			expectedErr:   errors.New("generating service principal access token with certificate"),
		},
		{
			name: "UserAssignedIdentityID is specified in cloud provider config",
			setCloudProviderConfig: func(t *testing.T, config *cloud.ProviderConfig) {
				config.UserAssignedIdentityID = "kubelet-identity-id"
				config.ClientID = clientIDForMSI
			},
			getTokenCredentialFunc: func(_ context.Context, _ *Config) (azcore.TokenCredential, error) {
				return &fake.TokenCredential{}, nil
			},
			expectedToken: "fake_token",
			expectedErr:   nil,
		},
		{
			name: "UserAssignedIdentityID is not specified in cloud provider config, but client ID indicates MSI usage",
			setCloudProviderConfig: func(t *testing.T, config *cloud.ProviderConfig) {
				config.UserAssignedIdentityID = ""
				config.ClientID = clientIDForMSI
			},
			expectedToken: "",
			expectedErr:   errors.New("client ID within cloud provider config indicates usage of a managed identity, though no user-assigned identity ID was provided"),
		},
		{
			name:           "a custom client ID is specified",
			customClientID: "custom",
			setCloudProviderConfig: func(t *testing.T, config *cloud.ProviderConfig) {
				config.UserAssignedIdentityID = "kubelet-identity-id"
				config.ClientID = clientIDForMSI
			},
			getTokenCredentialFunc: func(_ context.Context, _ *Config) (azcore.TokenCredential, error) {
				return &fake.TokenCredential{}, nil
			},
			expectedToken: "fake_token",
			expectedErr:   nil,
		},
		{
			name: "service principal client secret does not contain certificate data",
			setCloudProviderConfig: func(t *testing.T, config *cloud.ProviderConfig) {
				config.CloudName = azure.PublicCloud.Name
				config.ClientID = "service-principal-id"
				config.ClientSecret = "secret"
			},
			getTokenCredentialFunc: func(_ context.Context, _ *Config) (azcore.TokenCredential, error) {
				return &fake.TokenCredential{}, nil
			},
			expectedToken: "fake_token",
			expectedErr:   nil,
		},
		{
			name: "service principal client secret contains certificate data",
			setCloudProviderConfig: func(t *testing.T, config *cloud.ProviderConfig) {
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
			getTokenCredentialFunc: func(_ context.Context, _ *Config) (azcore.TokenCredential, error) {
				return &fake.TokenCredential{}, nil
			},
			expectedToken: "fake_token",
			expectedErr:   nil,
		},
		{
			name: "service principal client secret is b64-decoded and contains certificate data",
			setCloudProviderConfig: func(t *testing.T, config *cloud.ProviderConfig) {
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
			getTokenCredentialFunc: func(_ context.Context, _ *Config) (azcore.TokenCredential, error) {
				return &fake.TokenCredential{}, nil
			},
			expectedToken: "fake_token",
			expectedErr:   nil,
		},
	}

	testTenantID := "d87a2c3e-0c0c-42b2-a883-e48cd8723e22"
	testResource := "resource"

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ctx := log.NewTestContext()

			client := &client{
				getTokenCredentialFunc: c.getTokenCredentialFunc,
			}
			if client.getTokenCredentialFunc == nil {
				client.getTokenCredentialFunc = getTokenCredential
			}
			cloudProviderConfig := &cloud.ProviderConfig{
				TenantID: testTenantID,
			}
			c.setCloudProviderConfig(t, cloudProviderConfig)

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

func TestAADResourceToScope(t *testing.T) {
	cases := []struct {
		name          string
		resource      string
		expectedScope string
	}{
		{
			name:          "resource without trailing slash gets /.default appended",
			resource:      "https://management.azure.com",
			expectedScope: "https://management.azure.com/.default",
		},
		{
			name:          "resource with trailing slash gets /.default appended (slash removed first)",
			resource:      "https://management.azure.com/",
			expectedScope: "https://management.azure.com/.default",
		},
		{
			name:          "resource already ending in /.default is unchanged",
			resource:      "https://management.azure.com/.default",
			expectedScope: "https://management.azure.com/.default",
		},
		{
			name:          "simple resource string",
			resource:      "resource",
			expectedScope: "resource/.default",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			scope := aadResourceToScope(c.resource)
			assert.Equal(t, c.expectedScope, scope)
		})
	}
}
