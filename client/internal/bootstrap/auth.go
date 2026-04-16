// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package bootstrap

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/Azure/aks-secure-tls-bootstrap/client/internal/cloud"
	"github.com/Azure/aks-secure-tls-bootstrap/client/internal/http"
	"github.com/Azure/aks-secure-tls-bootstrap/client/internal/log"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"go.uber.org/zap"
)

const (
	// service principal secrets containing this prefix are PFX certificates which need to be decoded,
	// rather than raw password / secret strings
	certificateSecretPrefix = "certificate:"
)

const (
	// this will be the exact value of the "userAssignedIdentityID" field of the cloud provider config
	// when the node is using a (user-assigned) managed identity, rather than a service principal
	clientIDForMSI = "msi"
)

// getTokenCredentialFunc creates an azcore.TokenCredential based on the provided bootstrap configuration.
type getTokenCredentialFunc func(ctx context.Context, config *Config) (azcore.TokenCredential, error)

func (c *client) getToken(ctx context.Context, config *Config) (string, error) {
	credential, err := c.getTokenCredentialFunc(ctx, config)
	if err != nil {
		return "", err
	}
	token, err := credential.GetToken(ctx, policy.TokenRequestOptions{
		Scopes: []string{config.AADResource},
	})
	if err != nil {
		return "", err
	}
	return token.Token, nil
}

// getTokenCredential builds an azcore.TokenCredential from the provided bootstrap configuration,
// selecting between managed identity and service principal credential types as appropriate.
func getTokenCredential(ctx context.Context, config *Config) (azcore.TokenCredential, error) {
	logger := log.MustGetLogger(ctx)

	userAssignedID := config.CloudProviderConfig.UserAssignedIdentityID
	if config.UserAssignedIdentityID != "" {
		userAssignedID = config.UserAssignedIdentityID
	}

	if userAssignedID != "" {
		logger.Info("generating MSI access token", zap.String("clientId", userAssignedID))
		cred, err := azidentity.NewManagedIdentityCredential(&azidentity.ManagedIdentityCredentialOptions{
			ID:            azidentity.ClientID(userAssignedID),
			ClientOptions: http.GetDefaultAzureClientOpts(),
		})
		if err != nil {
			return nil, fmt.Errorf("generating MSI access token: %w", err)
		}
		return cred, nil
	}

	if config.CloudProviderConfig.ClientID == clientIDForMSI {
		return nil, fmt.Errorf("client ID within cloud provider config indicates usage of a managed identity, though no user-assigned identity ID was provided")
	}

	return getServicePrincipalCredential(ctx, config.CloudProviderConfig)
}

func getServicePrincipalCredential(ctx context.Context, cloudProviderConfig *cloud.ProviderConfig) (azcore.TokenCredential, error) {
	logger := log.MustGetLogger(ctx)

	secret := maybeB64Decode(cloudProviderConfig.ClientSecret)

	cloudConfig, err := cloud.GetCloudConfig(cloudProviderConfig.CloudName)
	if err != nil {
		return nil, fmt.Errorf("getting azure environment config for cloud %q: %w", cloudProviderConfig.CloudName, err)
	}

	if !strings.HasPrefix(secret, certificateSecretPrefix) {
		logger.Info("generating service principal access token with client secret", zap.String("clientId", cloudProviderConfig.ClientID))
		if secret == "" {
			return nil, fmt.Errorf("generating service principal access token with client secret: client secret is empty")
		}
		credential, err := azidentity.NewClientSecretCredential(cloudProviderConfig.TenantID, cloudProviderConfig.ClientID, secret,
			&azidentity.ClientSecretCredentialOptions{
				ClientOptions: http.GetDefaultAzureClientOptsWithCloud(cloudConfig),
			},
		)
		if err != nil {
			return nil, fmt.Errorf("generating service principal access token with client secret: %w", err)
		}
		return credential, nil
	}

	logger.Info("client secret contains certificate data, using certificate to generate service principal access token", zap.String("clientId", cloudProviderConfig.ClientID))

	certData, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(secret, certificateSecretPrefix))
	if err != nil {
		return nil, fmt.Errorf("b64-decoding certificate data in client secret: %w", err)
	}
	certs, key, err := azidentity.ParseCertificates(certData, nil)
	if err != nil {
		return nil, fmt.Errorf("decoding pfx certificate data in client secret: %w", err)
	}

	logger.Info("generating service principal access token with certificate", zap.String("clientId", cloudProviderConfig.ClientID))
	credential, err := azidentity.NewClientCertificateCredential(cloudProviderConfig.TenantID, cloudProviderConfig.ClientID, certs, key,
		&azidentity.ClientCertificateCredentialOptions{
			ClientOptions: http.GetDefaultAzureClientOptsWithCloud(cloudConfig),
		},
	)
	if err != nil {
		return nil, fmt.Errorf("generating service principal access token with certificate: %w", err)
	}

	return credential, nil
}

func maybeB64Decode(str string) string {
	if decoded, err := base64.StdEncoding.DecodeString(str); err == nil {
		return string(decoded)
	}
	return str
}
