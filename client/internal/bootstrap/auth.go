// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package bootstrap

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/Azure/aks-secure-tls-bootstrap/client/internal/cloud"
	"github.com/Azure/aks-secure-tls-bootstrap/client/internal/log"
	"github.com/Azure/go-autorest/autorest/adal"
	"github.com/Azure/go-autorest/autorest/azure"
	"go.uber.org/zap"
)

const (
	// service principal secrets containing this prefix are PFX certificates which need to be decoded,
	// rather than raw password / secret strings
	certificateSecretPrefix = "certificate:"
)

const (
	// this will be the exact value of the "userAssignedIdentityID" field of the cloud provider config (azure.json)
	// when the node is using a (user-assigned) managed identity, rather than a service principal
	clientIDForMSI = "msi"
)

const (
	// to avoid falling too deep into exponential backoff implemented by adal, which follows the public retry guidance:
	// https://learn.microsoft.com/en-us/entra/identity/managed-identities-azure-resources/how-to-use-vm-token#retry-guidance
	maxMSIRefreshAttempts = 5
)

// extractAccessTokenFunc extracts an oauth access token from the specified service principal token after a refresh, fake implementations given in unit tests.
type extractAccessTokenFunc func(ctx context.Context, token *adal.ServicePrincipalToken, isMSI bool) (string, error)

func extractAccessToken(ctx context.Context, token *adal.ServicePrincipalToken, isMSI bool) (string, error) {
	if err := token.RefreshWithContext(ctx); err != nil {
		return "", err
	}
	return token.OAuthToken(), nil
}

func (c *client) getToken(ctx context.Context, config *Config) (string, error) {
	logger := log.MustGetLogger(ctx)

	userAssignedID := getUserAssignedIdentityID(config)

	if userAssignedID != "" {
		logger.Info("generating MSI access token", zap.String("clientId", userAssignedID))
		msiToken, err := adal.NewServicePrincipalTokenFromManagedIdentity(config.AADResource, &adal.ManagedIdentityOptions{
			ClientID: userAssignedID,
		})
		if err != nil {
			return "", fmt.Errorf("generating MSI access token: %w", err)
		}
		msiToken.MaxMSIRefreshAttempts = maxMSIRefreshAttempts
		return c.extractAccessTokenFunc(ctx, msiToken, true)
	}

	if config.CloudProviderConfig.ClientID == clientIDForMSI {
		return "", fmt.Errorf("client ID within cloud provider config indicates usage of a managed identity, though no user-assigned identity ID was provided")
	}

	servicePrincipalToken, err := getServicePrincipalToken(ctx, config.AADResource, config.CloudProviderConfig)
	if err != nil {
		return "", err
	}

	return c.extractAccessTokenFunc(ctx, servicePrincipalToken, false)
}

func getUserAssignedIdentityID(config *Config) string {
	if config == nil {
		return ""
	}
	if config.UserAssignedIdentityID != "" {
		return config.UserAssignedIdentityID
	}
	if config.CloudProviderConfig == nil {
		return ""
	}
	return config.CloudProviderConfig.UserAssignedIdentityID
}

func isManagedIdentityTokenRequest(config *Config) bool {
	if getUserAssignedIdentityID(config) != "" {
		return true
	}
	return config != nil && config.CloudProviderConfig != nil && config.CloudProviderConfig.ClientID == clientIDForMSI
}

func isTerminalGetTokenError(err error, config *Config) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return true
	}

	var tokenRefreshErr adal.TokenRefreshError
	if !errors.As(err, &tokenRefreshErr) {
		return true
	}

	resp := tokenRefreshErr.Response()
	if resp == nil {
		return false
	}

	switch resp.StatusCode {
	case http.StatusTooManyRequests, http.StatusRequestTimeout:
		return false
	case http.StatusNotFound, http.StatusGone:
		return !isManagedIdentityTokenRequest(config)
	case http.StatusBadRequest:
		return !isRetryableManagedIdentityNotFoundError(err, config)
	default:
		return resp.StatusCode >= http.StatusBadRequest && resp.StatusCode < http.StatusInternalServerError
	}
}

func isRetryableManagedIdentityNotFoundError(err error, config *Config) bool {
	return isManagedIdentityTokenRequest(config) && strings.Contains(strings.ToLower(err.Error()), "identity not found")
}

func getServicePrincipalToken(ctx context.Context, resource string, cloudProviderConfig *cloud.ProviderConfig) (*adal.ServicePrincipalToken, error) {
	logger := log.MustGetLogger(ctx)

	secret := maybeB64Decode(cloudProviderConfig.ClientSecret)

	env, err := azure.EnvironmentFromName(cloudProviderConfig.CloudName)
	if err != nil {
		return nil, fmt.Errorf("getting azure environment config for cloud %q: %w", cloudProviderConfig.CloudName, err)
	}
	oauthConfig, err := adal.NewOAuthConfig(env.ActiveDirectoryEndpoint, cloudProviderConfig.TenantID)
	if err != nil {
		return nil, fmt.Errorf("creating oauth config with azure environment: %w", err)
	}

	if !strings.HasPrefix(secret, certificateSecretPrefix) {
		logger.Info("generating service principal access token with client secret", zap.String("clientId", cloudProviderConfig.ClientID))
		token, err := adal.NewServicePrincipalToken(*oauthConfig, cloudProviderConfig.ClientID, secret, resource)
		if err != nil {
			return nil, fmt.Errorf("generating service principal access token with client secret: %w", err)
		}
		return token, nil
	}

	logger.Info("client secret contains certificate data, using certificate to generate service principal access token", zap.String("clientId", cloudProviderConfig.ClientID))

	certData, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(secret, certificateSecretPrefix))
	if err != nil {
		return nil, fmt.Errorf("b64-decoding certificate data in client secret: %w", err)
	}
	certificate, privateKey, err := adal.DecodePfxCertificateData(certData, "")
	if err != nil {
		return nil, fmt.Errorf("decoding pfx certificate data in client secret: %w", err)
	}

	logger.Info("generating service principal access token with certificate", zap.String("clientId", cloudProviderConfig.ClientID))
	token, err := adal.NewServicePrincipalTokenFromCertificate(*oauthConfig, cloudProviderConfig.ClientID, certificate, privateKey, resource)
	if err != nil {
		return nil, fmt.Errorf("generating service principal access token with certificate: %w", err)
	}

	return token, nil
}

func maybeB64Decode(str string) string {
	if decoded, err := base64.StdEncoding.DecodeString(str); err == nil {
		return string(decoded)
	}
	return str
}
