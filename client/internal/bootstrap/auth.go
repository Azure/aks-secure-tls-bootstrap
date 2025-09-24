// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package bootstrap

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/Azure/aks-secure-tls-bootstrap/client/internal/cloud"
	"github.com/Azure/aks-secure-tls-bootstrap/client/internal/log"
	"github.com/Azure/aks-secure-tls-bootstrap/client/internal/telemetry"
	"github.com/Azure/go-autorest/autorest/adal"
	"github.com/Azure/go-autorest/autorest/azure"
)

const (
	certificateSecretPrefix = "certificate:"
)

const (
	clientIDForMSI = "msi"
)

const (
	maxMSIRefreshAttempts = 3
)

// extractAccessTokenFunc extracts an oauth access token from the specified service principal token after a refresh, fake implementations given in unit tests.
type extractAccessTokenFunc func(token *adal.ServicePrincipalToken) (string, error)

func extractAccessToken(token *adal.ServicePrincipalToken) (string, error) {
	if err := token.Refresh(); err != nil {
		return "", &bootstrapError{
			errorType: ErrorTypeGetAccessTokenFailure,
			retryable: true,
			inner:     fmt.Errorf("obtaining fresh access token: %w", err),
		}
	}
	return token.OAuthToken(), nil
}

// getAccessToken retrieves an AAD access token (JWT) using the specified custom client ID, resource, and cloud provider config.
// MSI access tokens are retrieved from IMDS, while service principal tokens are retrieved directly from AAD.
func (c *client) getAccessToken(ctx context.Context, customClientID, resource string, cloudProviderConfig *cloud.ProviderConfig) (string, error) {
	endSpan := telemetry.StartSpan(ctx, "GetAccessToken")
	defer endSpan()

	logger := log.MustGetLogger(ctx)

	userAssignedID := cloudProviderConfig.UserAssignedIdentityID
	if customClientID != "" {
		userAssignedID = customClientID
	}

	if userAssignedID != "" {
		logger.Infof("generating MSI access token (clientId: %s)", userAssignedID)
		token, err := adal.NewServicePrincipalTokenFromManagedIdentity(resource, &adal.ManagedIdentityOptions{
			ClientID: userAssignedID,
		})
		if err != nil {
			return "", makeNonRetryableGetAccessTokenFailure(fmt.Errorf("generating MSI access token: %w", err))
		}
		// to avoid falling too deep into exponential backoff implemented by adal, which follows the public retry guidance:
		// https://learn.microsoft.com/en-us/entra/identity/managed-identities-azure-resources/how-to-use-vm-token#retry-guidance
		token.MaxMSIRefreshAttempts = maxMSIRefreshAttempts
		return c.extractAccessTokenFunc(token)
	}

	if cloudProviderConfig.ClientID == clientIDForMSI {
		return "", makeNonRetryableGetAccessTokenFailure(fmt.Errorf("client ID within cloud provider config indicates usage of a managed identity, though no user-assigned identity ID was provided"))
	}

	env, err := azure.EnvironmentFromName(cloudProviderConfig.CloudName)
	if err != nil {
		return "", makeNonRetryableGetAccessTokenFailure(fmt.Errorf("getting azure environment config for cloud %q: %w", cloudProviderConfig.CloudName, err))
	}
	oauthConfig, err := adal.NewOAuthConfig(env.ActiveDirectoryEndpoint, cloudProviderConfig.TenantID)
	if err != nil {
		return "", makeNonRetryableGetAccessTokenFailure(fmt.Errorf("creating oauth config with azure environment: %w", err))
	}

	if !strings.HasPrefix(cloudProviderConfig.ClientSecret, certificateSecretPrefix) {
		logger.Infof("generating SPN access token with username and password (clientId: %s)", cloudProviderConfig.ClientID)
		token, err := adal.NewServicePrincipalToken(*oauthConfig, cloudProviderConfig.ClientID, cloudProviderConfig.ClientSecret, resource)
		if err != nil {
			return "", makeNonRetryableGetAccessTokenFailure(fmt.Errorf("generating SPN access token with username and password: %w", err))
		}
		return c.extractAccessTokenFunc(token)
	}

	logger.Infof("client secret contains certificate data, using certificate to generate SPN access token (clientId: %s)", cloudProviderConfig.ClientID)

	certData, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(cloudProviderConfig.ClientSecret, certificateSecretPrefix))
	if err != nil {
		return "", makeNonRetryableGetAccessTokenFailure(fmt.Errorf("b64-decoding certificate data in client secret: %w", err))
	}
	certificate, privateKey, err := adal.DecodePfxCertificateData(certData, "")
	if err != nil {
		return "", makeNonRetryableGetAccessTokenFailure(fmt.Errorf("decoding pfx certificate data in client secret: %w", err))
	}

	logger.Infof("generating SPN access token with certificate (clientId: %s)", cloudProviderConfig.ClientID)
	token, err := adal.NewServicePrincipalTokenFromCertificate(*oauthConfig, cloudProviderConfig.ClientID, certificate, privateKey, resource)
	if err != nil {
		return "", makeNonRetryableGetAccessTokenFailure(fmt.Errorf("generating SPN access token with certificate: %w", err))
	}

	return c.extractAccessTokenFunc(token)
}
