// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package client

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/Azure/aks-tls-bootstrap-client/pkg/datamodel"
)

// getAuthToken retrieves the auth token (JWT) from AAD used to validate the node's identity with the bootstrap server.
// If the user specifies their own client ID, meaning they've brought their own node, we assume that they're specifying
// a user-assigned managed identity and thus fetch the corresponding MSI token from IMDS. Otherwise, the information specified
// in the azure config read from azure.json to infer the identity type and either request the token from AAD directly, or from IMDS.
// All tokens for MSIs will be fetched from IMDS, while all SPN tokens will be fetched from AAD directly.
func (c *tlsBootstrapClientImpl) getAuthToken(ctx context.Context, userSpecifiedClientID string, azureConfig *datamodel.AzureConfig) (string, error) {
	if userSpecifiedClientID != "" {
		c.logger.Info("retrieving MSI access token from IMDS using user-specified client ID for UAMI...")
		tokenResponse, err := c.imdsClient.GetMSIToken(ctx, baseImdsURL, userSpecifiedClientID)
		if err != nil {
			return "", fmt.Errorf("unable to get MSI token for UAMI using user-specified client ID")
		}
		return tokenResponse.AccessToken, nil
	}

	if azureConfig == nil {
		return "", fmt.Errorf("unable to get auth token: azure config is nil")
	}
	if azureConfig.ClientID == "" {
		return "", fmt.Errorf("unable to infer node identity type: client ID in azure.json is empty")
	}
	if azureConfig.ClientID == managedServiceIdentity {
		c.logger.Info("retrieving MSI access token from IMDS...")
		var clientID string
		if azureConfig.UserAssignedIdentityID != "" {
			clientID = azureConfig.UserAssignedIdentityID
		}
		tokenResponse, err := c.imdsClient.GetMSIToken(ctx, baseImdsURL, clientID)
		if err != nil {
			return "", fmt.Errorf("unable to get MSI token from IMDS: %w", err)
		}
		return tokenResponse.AccessToken, nil
	}

	c.logger.Info("retrieving SP access token from AAD...")
	if azureConfig.ClientSecret == "" {
		return "", fmt.Errorf("cannot retrieve SP token from AAD: azure.json missing clientSecret")
	}
	if azureConfig.TenantID == "" {
		return "", fmt.Errorf("cannot retrieve SP token from AAD: azure.json missing tenantId")
	}
	token, err := c.aadClient.GetAadToken(
		ctx,
		azureConfig.ClientID,
		azureConfig.ClientSecret,
		azureConfig.TenantID,
	)
	if err != nil {
		return "", fmt.Errorf("unable to get SPN token from AAD: %w", err)
	}
	return token, nil

}

func loadAzureJSON() (*datamodel.AzureConfig, error) {
	if isWindows() {
		return loadAzureJSONFromPath(defaultWindowsAzureJSONPath)
	}
	return loadAzureJSONFromPath(defaultLinuxAzureJSONPath)
}

func loadAzureJSONFromPath(path string) (*datamodel.AzureConfig, error) {
	azureJSON, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to parse %s", path)
	}

	azureConfig := &datamodel.AzureConfig{}
	if err = json.Unmarshal(azureJSON, azureConfig); err != nil {
		return nil, fmt.Errorf("failed to unmarshal %s", path)
	}

	return azureConfig, nil
}
