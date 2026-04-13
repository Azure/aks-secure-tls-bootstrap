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
	"github.com/Azure/aks-secure-tls-bootstrap/client/internal/telemetry"
	"github.com/Azure/aks-secure-tls-bootstrap/client/internal/testutil"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/fake"
	azcloud "github.com/Azure/azure-sdk-for-go/sdk/azcore/cloud"
)

const (
	// testCloudNamePublic is the mixed-case cloud name as would appear in azure.json, used to drive tests.
	testCloudNamePublic = "AzurePublicCloud"
)

func TestGetToken(t *testing.T) {
	cases := []struct {
		name                    string
		customClientID          string
		setupCloudProviderConfig func(t *testing.T, config *cloud.ProviderConfig)
		// credentialFactory overrides newCredentialFromConfig for cases that need to
		// control GetToken behavior. When nil, newCredentialFromConfig is used (which
		// exercises real credential-creation logic, including any error paths).
		credentialFactory credentialFactoryFunc
		expectedToken     string
		expectedErr       error
	}{
		{
			name: "error getting azure environment config for specified cloud",
			setupCloudProviderConfig: func(t *testing.T, config *cloud.ProviderConfig) {
				config.CloudName = "invalid"
				config.ClientID = "service-principal-id"
				config.ClientSecret = "secret"
			},
			// nil credentialFactory → newCredentialFromConfig runs → error returned from cloudConfigFromName
			expectedToken: "",
			expectedErr:   errors.New(`getting azure environment config for cloud "invalid"`),
		},
		{
			name: "error generating a service principal access token with client secret due to missing client secret",
			setupCloudProviderConfig: func(t *testing.T, config *cloud.ProviderConfig) {
				config.CloudName = testCloudNamePublic
				config.ClientID = "service-principal-id"
				config.ClientSecret = ""
			},
			// nil credentialFactory → newCredentialFromConfig runs → error returned from getServicePrincipalCredential
			expectedToken: "",
			expectedErr:   errors.New("generating service principal access token with client secret"),
		},
		{
			name: "error b64-decoding client secret certificate data",
			setupCloudProviderConfig: func(t *testing.T, config *cloud.ProviderConfig) {
				config.CloudName = testCloudNamePublic
				config.ClientID = "service-principal-id"
				config.ClientSecret = "certificate:YW55IGNhcm5hbCBwbGVhc3U======" // invalid b64-encoding
			},
			// nil credentialFactory → newCredentialFromConfig runs → error returned from getServicePrincipalCredential
			expectedToken: "",
			expectedErr:   errors.New("b64-decoding certificate data in client secret"),
		},
		{
			name: "error pfx-decoding client secret certificate data",
			setupCloudProviderConfig: func(t *testing.T, config *cloud.ProviderConfig) {
				config.CloudName = testCloudNamePublic
				config.ClientID = "service-principal-id"
				config.ClientSecret = "certificate:dGVzdAo=" // b64-encoding of "test"
			},
			// nil credentialFactory → newCredentialFromConfig runs → error returned from getServicePrincipalCredential
			expectedToken: "",
			expectedErr:   errors.New("decoding pfx certificate data in client secret"),
		},
		{
			name: "error returned from GetToken",
			setupCloudProviderConfig: func(t *testing.T, config *cloud.ProviderConfig) {
				certData, err := testutil.GenerateCertAndKeyAsEncodedPFXData(testutil.CertTemplate{
					CommonName:   "aad",
					Organization: "azure",
					Expiration:   time.Now().Add(time.Hour),
				})
				assert.NoError(t, err)

				config.CloudName = testCloudNamePublic
				config.ClientID = "service-principal-id"
				config.ClientSecret = "certificate:" + certData
			},
			credentialFactory: func(_ context.Context, _ *Config) (azcore.TokenCredential, error) {
				fakeCred := &fake.TokenCredential{}
				fakeCred.SetError(errors.New("generating service principal access token with certificate"))
				return fakeCred, nil
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
			credentialFactory: func(_ context.Context, _ *Config) (azcore.TokenCredential, error) {
				return &fake.TokenCredential{}, nil
			},
			expectedToken: "fake_token",
			expectedErr:   nil,
		},
		{
			name: "UserAssignedIdentityID is not specified in cloud provider config, but client ID indicates MSI usage",
			setupCloudProviderConfig: func(t *testing.T, config *cloud.ProviderConfig) {
				config.UserAssignedIdentityID = ""
				config.ClientID = clientIDForMSI
			},
			// nil credentialFactory → newCredentialFromConfig runs → error returned for clientIDForMSI with no userAssignedID
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
			credentialFactory: func(_ context.Context, _ *Config) (azcore.TokenCredential, error) {
				return &fake.TokenCredential{}, nil
			},
			expectedToken: "fake_token",
			expectedErr:   nil,
		},
		{
			name: "service principal client secret does not contain certificate data",
			setupCloudProviderConfig: func(t *testing.T, config *cloud.ProviderConfig) {
				config.CloudName = testCloudNamePublic
				config.ClientID = "service-principal-id"
				config.ClientSecret = "secret"
			},
			credentialFactory: func(_ context.Context, _ *Config) (azcore.TokenCredential, error) {
				return &fake.TokenCredential{}, nil
			},
			expectedToken: "fake_token",
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

				config.CloudName = testCloudNamePublic
				config.ClientID = "service-principal-id"
				config.ClientSecret = "certificate:" + certData
			},
			credentialFactory: func(_ context.Context, _ *Config) (azcore.TokenCredential, error) {
				return &fake.TokenCredential{}, nil
			},
			expectedToken: "fake_token",
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

				config.CloudName = testCloudNamePublic
				config.ClientID = "service-principal-id"
				config.ClientSecret = base64.StdEncoding.EncodeToString([]byte("certificate:" + certData))
			},
			credentialFactory: func(_ context.Context, _ *Config) (azcore.TokenCredential, error) {
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
			ctx := telemetry.WithTracing(log.NewTestContext())

			credentialFactory := c.credentialFactory
			if credentialFactory == nil {
				credentialFactory = newCredentialFromConfig
			}
			client := &client{
				credentialFactory: credentialFactory,
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

func TestCloudConfigFromName(t *testing.T) {
	cases := []struct {
		name          string
		cloudName     string
		expectedCloud azcloud.Configuration
		expectedErr   error
	}{
		{
			name:        "empty cloud name returns error",
			cloudName:   "",
			expectedErr: errors.New(`unsupported cloud name: ""`),
		},
		{
			name:          "AzurePublicCloud maps to AzurePublic",
			cloudName:     "AzurePublicCloud",
			expectedCloud: azcloud.AzurePublic,
		},
		{
			name:          "cloud name is case-insensitive",
			cloudName:     "azurepubliccloud",
			expectedCloud: azcloud.AzurePublic,
		},
		{
			name:          "AzureUSGovernmentCloud maps to AzureGovernment",
			cloudName:     "AzureUSGovernmentCloud",
			expectedCloud: azcloud.AzureGovernment,
		},
		{
			name:          "AzureChinaCloud maps to AzureChina",
			cloudName:     "AzureChinaCloud",
			expectedCloud: azcloud.AzureChina,
		},
		{
			name:        "unsupported cloud name returns error",
			cloudName:   "AzureGermanCloud",
			expectedErr: errors.New(`unsupported cloud name: "AzureGermanCloud"`),
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cloudConfig, err := cloudConfigFromName(c.cloudName)
			if c.expectedErr != nil {
				assert.ErrorContains(t, err, c.expectedErr.Error())
			} else {
				assert.NoError(t, err)
				assert.Equal(t, c.expectedCloud, cloudConfig)
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

