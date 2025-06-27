// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package bootstrap

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/Azure/aks-secure-tls-bootstrap/client/internal/cloud"
	"github.com/Azure/aks-secure-tls-bootstrap/client/internal/telemetry"
	"github.com/Azure/go-autorest/autorest/adal"
	"github.com/Azure/go-autorest/autorest/azure"
	"go.uber.org/zap"
)

const (
	certificateSecretPrefix = "certificate:"
)

const (
	maxMSIRefreshAttempts = 3
)

// extractAccessTokenFunc extracts an oauth access token from the specified service principal token after a refresh, fake implementations given in unit tests.
type extractAccessTokenFunc func(token *adal.ServicePrincipalToken) (string, error)

func extractAccessToken(token *adal.ServicePrincipalToken) (string, error) {
	if err := token.Refresh(); err != nil {
		return "", fmt.Errorf("obtaining fresh access token: %w", err)
	}
	return token.OAuthToken(), nil
}

// getAccessToken retrieves an AAD access token (JWT) using the specified custom client ID, resource, and cloud provider config.
// MSI access tokens are retrieved from IMDS, while service principal tokens are retrieved directly from AAD.
func (c *Client) getAccessToken(ctx context.Context, customClientID, resource string, cloudProviderConfig *cloud.ProviderConfig) (string, error) {
	spanName := "GetAccessToken"
	tracer := telemetry.MustGetTracer(ctx)
	tracer.StartSpan(spanName)
	defer tracer.EndSpan(spanName)

	userAssignedID := cloudProviderConfig.UserAssignedIdentityID
	if customClientID != "" {
		userAssignedID = customClientID
	}

	if userAssignedID != "" {
		c.logger.Info("generating MSI access token", zap.String("clientId", userAssignedID))
		token, err := adal.NewServicePrincipalTokenFromManagedIdentity(resource, &adal.ManagedIdentityOptions{
			ClientID: userAssignedID,
		})
		if err != nil {
			return "", fmt.Errorf("generating MSI access token: %w", err)
		}
		// to avoid falling too deep into exponential backoff implemented by adal, which follows the public retry guidance
		// https://learn.microsoft.com/en-us/entra/identity/managed-identities-azure-resources/how-to-use-vm-token#retry-guidance
		token.MaxMSIRefreshAttempts = maxMSIRefreshAttempts
		return c.extractAccessTokenFunc(token)
	}

	env, err := azure.EnvironmentFromName(cloudProviderConfig.CloudName)
	if err != nil {
		return "", fmt.Errorf("getting azure environment config for cloud %q: %w", cloudProviderConfig.CloudName, err)
	}
	oauthConfig, err := adal.NewOAuthConfig(env.ActiveDirectoryEndpoint, cloudProviderConfig.TenantID)
	if err != nil {
		return "", fmt.Errorf("creating oauth config with azure environment: %w", err)
	}

	if !strings.HasPrefix(cloudProviderConfig.ClientSecret, certificateSecretPrefix) {
		c.logger.Info("generating SPN access token with username and password", zap.String("clientId", cloudProviderConfig.ClientID))
		token, err := adal.NewServicePrincipalToken(*oauthConfig, cloudProviderConfig.ClientID, cloudProviderConfig.ClientSecret, resource)
		if err != nil {
			return "", fmt.Errorf("generating SPN access token with username and password: %w", err)
		}
		return c.extractAccessTokenFunc(token)
	}

	c.logger.Info("client secret contains certificate data, using certificate to generate SPN access token", zap.String("clientId", cloudProviderConfig.ClientID))

	certData, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(cloudProviderConfig.ClientSecret, certificateSecretPrefix))
	if err != nil {
		return "", fmt.Errorf("b64-decoding certificate data in client secret: %w", err)
	}
	certificate, privateKey, err := adal.DecodePfxCertificateData(certData, "")
	if err != nil {
		return "", fmt.Errorf("decoding pfx certificate data in client secret: %w", err)
	}

	c.logger.Info("generating SPN access token with certificate", zap.String("clientId", cloudProviderConfig.ClientID))
	token, err := adal.NewServicePrincipalTokenFromCertificate(*oauthConfig, cloudProviderConfig.ClientID, certificate, privateKey, resource)
	if err != nil {
		return "", fmt.Errorf("generating SPN access token with certificate: %w", err)
	}

	return c.extractAccessTokenFunc(token)
}
