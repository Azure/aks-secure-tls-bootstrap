// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package bootstrap

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/Azure/aks-secure-tls-bootstrap/client/internal/datamodel"
	"github.com/Azure/go-autorest/autorest/adal"
	"github.com/Azure/go-autorest/autorest/azure"
	"go.uber.org/zap"
)

const (
	certificateSecretPrefix = "certificate:"
)

// getMSITokenFunc returns an MSI access token with the specified options, fake implementations given in unit tests.
type getMSITokenFunc func(resource string, options *adal.ManagedIdentityOptions, callbacks ...adal.TokenRefreshCallback) (*adal.ServicePrincipalToken, error)

// getServicePrincipalTokenFunc returns a service principal access token with the specified options, fake implementations given in unit tests.
type getServicePrincipalTokenFunc func(oauthConfig adal.OAuthConfig, clientID string, secret string, resource string, callbacks ...adal.TokenRefreshCallback) (*adal.ServicePrincipalToken, error)

// getServicePrincipalTokenWithCertFunc returns a service principal access token using a certificate with the specified options, fake implementations given in unit tests.
type getServicePrincipalTokenWithCertFunc func(oauthConfig adal.OAuthConfig, clientID string, certificate *x509.Certificate, privateKey *rsa.PrivateKey, resource string, callbacks ...adal.TokenRefreshCallback) (*adal.ServicePrincipalToken, error)

// extractAccessTokenFunc extracts an oauth access token from the specified service principal token, fake implementations given in unit tests.
type extractAccessTokenFunc func(servicePrincipalToken *adal.ServicePrincipalToken) string

func extractAccessToken(servicePrincipalToken *adal.ServicePrincipalToken) string {
	return servicePrincipalToken.OAuthToken()
}

// getAccessToken retrieves an AAD access token (JWT) using the specified custom client ID, resource, and azure config.
// MSI access tokens are retrieved from IMDS, while service principal tokens are retrieved directly from AAD.
func (c *Client) getAccessToken(customClientID, resource string, azureConfig *datamodel.AzureConfig) (string, error) {
	userAssignedID := azureConfig.UserAssignedIdentityID
	if customClientID != "" {
		userAssignedID = customClientID
	}

	if userAssignedID != "" {
		c.logger.Info("generating MSI access token", zap.String("clientId", userAssignedID))
		token, err := c.getMSITokenFunc(resource, &adal.ManagedIdentityOptions{
			ClientID: userAssignedID,
		})
		if err != nil {
			return "", fmt.Errorf("generating MSI access token: %w", err)
		}
		return c.extractAccessTokenFunc(token), nil
	}

	env, err := azure.EnvironmentFromName(azureConfig.Cloud)
	if err != nil {
		return "", fmt.Errorf("getting azure environment config for cloud %q: %w", azureConfig.Cloud, err)
	}
	oauthConfig, err := adal.NewOAuthConfig(env.ActiveDirectoryEndpoint, azureConfig.TenantID)
	if err != nil {
		return "", fmt.Errorf("creating oauth config with azure environment: %w", err)
	}

	if !strings.HasPrefix(azureConfig.ClientSecret, certificateSecretPrefix) {
		c.logger.Info("generating SPN access token with username and password", zap.String("clientId", azureConfig.ClientID))
		token, err := c.getServicePrincipalTokenFunc(*oauthConfig, azureConfig.ClientID, azureConfig.ClientSecret, resource)
		if err != nil {
			return "", fmt.Errorf("generating SPN access token with username and password: %w", err)
		}
		return c.extractAccessTokenFunc(token), nil
	}

	c.logger.Info("client secret contains certificate data, using certificate to generate SPN access token", zap.String("clientId", azureConfig.ClientID))

	certData, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(azureConfig.ClientSecret, certificateSecretPrefix))
	if err != nil {
		return "", fmt.Errorf("b64-decoding certificate data in client secret: %w", err)
	}
	certificate, privateKey, err := adal.DecodePfxCertificateData(certData, "")
	if err != nil {
		return "", fmt.Errorf("decoding pfx certificate data in client secret: %w", err)
	}

	c.logger.Info("generating SPN access token with certificate", zap.String("clientId", azureConfig.ClientID))
	token, err := c.getServicePrincipalTokenWithCertFunc(*oauthConfig, azureConfig.ClientID, certificate, privateKey, resource)
	if err != nil {
		return "", fmt.Errorf("generating SPN access token with certificate: %w", err)
	}
	return c.extractAccessTokenFunc(token), nil
}
