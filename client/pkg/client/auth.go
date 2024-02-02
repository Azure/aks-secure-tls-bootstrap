// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package client

import (
	"context"
	"fmt"
)

// getAuthToken retrieves the auth token (JWT) from AAD used to validate the node's identity with the bootstrap server.
// If the user specifies their own client ID, meaning they've brought their own node, we assume that they're specifying
// a user-assigned managed identity and thus fetch the corresponding MSI token from IMDS. Otherwise, the information specified
// in the azure config read from azure.json to infer the identity type and either request the token from AAD directly, or from IMDS.
// All tokens for MSIs will be fetched from IMDS, while all SPN tokens will be fetched from AAD directly.
func (c *SecureTLSBootstrapClient) getAuthToken(ctx context.Context, customClientID, aadResource string) (string, error) {
	if customClientID != "" {
		c.logger.Info("retrieving MSI access token from IMDS using user-specified client ID for UAMI...")
		token, err := c.imdsClient.GetMSIToken(ctx, customClientID, aadResource)
		if err != nil {
			return "", fmt.Errorf("unable to get MSI token for UAMI using user-specified client ID")
		}
		return token, nil
	}

	if c.azureConfig == nil {
		return "", fmt.Errorf("unable to get auth token: azure config is nil")
	}
	if c.azureConfig.ClientID == "" {
		return "", fmt.Errorf("unable to infer node identity type: client ID in azure.json is empty")
	}
	if c.azureConfig.ClientID == managedServiceIdentity {
		c.logger.Info("retrieving MSI access token from IMDS...")
		var clientID string
		if c.azureConfig.UserAssignedIdentityID != "" {
			clientID = c.azureConfig.UserAssignedIdentityID
		}
		token, err := c.imdsClient.GetMSIToken(ctx, clientID, aadResource)
		if err != nil {
			return "", fmt.Errorf("unable to get MSI token from IMDS: %w", err)
		}
		return token, nil
	}

	c.logger.Info("retrieving SP access token from AAD...")
	if c.azureConfig.ClientSecret == "" {
		return "", fmt.Errorf("cannot retrieve SP token from AAD: azure.json missing clientSecret")
	}
	if c.azureConfig.TenantID == "" {
		return "", fmt.Errorf("cannot retrieve SP token from AAD: azure.json missing tenantId")
	}
	token, err := c.aadClient.GetToken(ctx, c.azureConfig, aadResource)
	if err != nil {
		return "", fmt.Errorf("unable to get SPN token from AAD: %w", err)
	}
	return token, nil

}
