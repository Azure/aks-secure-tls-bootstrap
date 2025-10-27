// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package bootstrap

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"

	"github.com/Azure/aks-secure-tls-bootstrap/client/internal/cloud"
	"github.com/Azure/aks-secure-tls-bootstrap/client/internal/imds"
	"github.com/Azure/aks-secure-tls-bootstrap/client/internal/log"
	"github.com/Azure/aks-secure-tls-bootstrap/client/internal/telemetry"
	"github.com/Azure/go-autorest/autorest/adal"
	"github.com/Azure/go-autorest/autorest/azure"
	"go.uber.org/zap"
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
type extractAccessTokenFunc func(ctx context.Context, oken *adal.ServicePrincipalToken, isMSI bool) (string, error)

func extractAccessToken(ctx context.Context, token *adal.ServicePrincipalToken, isMSI bool) (string, error) {
	if err := token.Refresh(); err != nil {
		return "", tokenRefreshErrorToGetAccessTokenFailure(ctx, err, isMSI)
	}
	return token.OAuthToken(), nil
}

func (c *client) getAccessToken(ctx context.Context, userAssignedIdentityID, resource string, cloudProviderConfig *cloud.ProviderConfig) (string, error) {
	endSpan := telemetry.StartSpan(ctx, "GetAccessToken")
	defer endSpan()

	logger := log.MustGetLogger(ctx)

	userAssignedID := cloudProviderConfig.UserAssignedIdentityID
	if userAssignedIdentityID != "" {
		userAssignedID = userAssignedIdentityID
	}

	if userAssignedID != "" {
		logger.Info("generating MSI access token", zap.String("clientId", userAssignedID))
		msiToken, err := adal.NewServicePrincipalTokenFromManagedIdentity(resource, &adal.ManagedIdentityOptions{
			ClientID: userAssignedID,
		})
		if err != nil {
			return "", makeNonRetryableGetAccessTokenFailure(fmt.Errorf("generating MSI access token: %w", err))
		}
		// to avoid falling too deep into exponential backoff implemented by adal, which follows the public retry guidance:
		// https://learn.microsoft.com/en-us/entra/identity/managed-identities-azure-resources/how-to-use-vm-token#retry-guidance
		msiToken.MaxMSIRefreshAttempts = maxMSIRefreshAttempts
		return c.extractAccessTokenFunc(ctx, msiToken, true)
	}

	if cloudProviderConfig.ClientID == clientIDForMSI {
		return "", makeNonRetryableGetAccessTokenFailure(fmt.Errorf("client ID within cloud provider config indicates usage of a managed identity, though no user-assigned identity ID was provided"))
	}

	servicePrincipalToken, err := getServicePrincipalToken(ctx, resource, cloudProviderConfig)
	if err != nil {
		return "", err
	}

	return c.extractAccessTokenFunc(ctx, servicePrincipalToken, false)
}

func getServicePrincipalToken(ctx context.Context, resource string, cloudProviderConfig *cloud.ProviderConfig) (*adal.ServicePrincipalToken, error) {
	logger := log.MustGetLogger(ctx)

	secret := maybeB64Decode(cloudProviderConfig.ClientSecret)

	env, err := azure.EnvironmentFromName(cloudProviderConfig.CloudName)
	if err != nil {
		return nil, makeNonRetryableGetAccessTokenFailure(fmt.Errorf("getting azure environment config for cloud %q: %w", cloudProviderConfig.CloudName, err))
	}
	oauthConfig, err := adal.NewOAuthConfig(env.ActiveDirectoryEndpoint, cloudProviderConfig.TenantID)
	if err != nil {
		return nil, makeNonRetryableGetAccessTokenFailure(fmt.Errorf("creating oauth config with azure environment: %w", err))
	}

	if !strings.HasPrefix(secret, certificateSecretPrefix) {
		logger.Info("generating service principal access token with client secret", zap.String("clientId", cloudProviderConfig.ClientID))
		token, err := adal.NewServicePrincipalToken(*oauthConfig, cloudProviderConfig.ClientID, secret, resource)
		if err != nil {
			return nil, makeNonRetryableGetAccessTokenFailure(fmt.Errorf("generating service principal access token with client secret: %w", err))
		}
		return token, nil
	}

	logger.Info("client secret contains certificate data, using certificate to generate service principal access token", zap.String("clientId", cloudProviderConfig.ClientID))

	certData, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(secret, certificateSecretPrefix))
	if err != nil {
		return nil, makeNonRetryableGetAccessTokenFailure(fmt.Errorf("b64-decoding certificate data in client secret: %w", err))
	}
	certificate, privateKey, err := adal.DecodePfxCertificateData(certData, "")
	if err != nil {
		return nil, makeNonRetryableGetAccessTokenFailure(fmt.Errorf("decoding pfx certificate data in client secret: %w", err))
	}

	logger.Info("generating service principal access token with certificate", zap.String("clientId", cloudProviderConfig.ClientID))
	token, err := adal.NewServicePrincipalTokenFromCertificate(*oauthConfig, cloudProviderConfig.ClientID, certificate, privateKey, resource)
	if err != nil {
		return nil, makeNonRetryableGetAccessTokenFailure(fmt.Errorf("generating service principal access token with certificate: %w", err))
	}

	return token, nil
}

func maybeB64Decode(str string) string {
	if decoded, err := base64.StdEncoding.DecodeString(str); err == nil {
		return string(decoded)
	}
	return str
}

func makeNonRetryableGetAccessTokenFailure(err error) error {
	return &bootstrapError{
		errorType: ErrorTypeGetAccessTokenFailure,
		retryable: false,
		inner:     err,
	}
}

func tokenRefreshErrorToGetAccessTokenFailure(ctx context.Context, err error, isMSI bool) error {
	bootstrapErr := &bootstrapError{
		errorType: ErrorTypeGetAccessTokenFailure,
		retryable: true, // optimistically consider the error retryable from the start
		inner:     fmt.Errorf("obtaining fresh access token: %w", err),
	}

	rerr, ok := err.(adal.TokenRefreshError)
	if !ok {
		return bootstrapErr
	}

	resp := rerr.Response()
	if resp == nil {
		return bootstrapErr
	}

	if !isMSI {
		bootstrapErr.retryable = resp.StatusCode >= http.StatusInternalServerError
		return bootstrapErr
	}

	if resp.StatusCode != http.StatusBadRequest {
		bootstrapErr.retryable = imds.IsRetryableHTTPStatusCode(resp.StatusCode)
		return bootstrapErr
	}

	// 400s aren't normally retryable, though identity assignment can sometimes take a bit of time to propagate to IMDS,
	// so we treat "Identity not found" errors as retryable
	bootstrapErr.retryable = strings.Contains(strings.ToLower(err.Error()), "identity not found")
	return bootstrapErr
}
