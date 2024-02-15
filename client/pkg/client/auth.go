// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package client

import (
	"context"
	"fmt"

	"github.com/Azure/aks-secure-tls-bootstrap/client/pkg/datamodel"
)

const (
	// The clientId used to denote Managed Service Identities (MSI).
	managedServiceIdentity = "msi"
)

// getAuthToken retrieves the auth token (JWT) from AAD used to validate the node's identity with the bootstrap server.
// If the user specifies their own client ID, meaning they've brought their own node, we assume that they're specifying
// a user-assigned managed identity and thus fetch the corresponding MSI token from IMDS. Otherwise, the information specified
// in the azure config read from azure.json to infer the identity type and either request the token from AAD directly, or from IMDS.
// All tokens for MSIs will be fetched from IMDS, while all SPN tokens will be fetched from AAD directly.
func (c *SecureTLSBootstrapClient) getAuthToken(ctx context.Context, customClientID, aadResource string, azureConfig *datamodel.AzureConfig) (string, error) {
	if customClientID != "" {
		c.logger.Info("retrieving MSI access token from IMDS using user-specified client ID for UAMI...")
		token, err := c.imdsClient.GetMSIToken(ctx, customClientID, aadResource)
		if err != nil {
			return "", fmt.Errorf("unable to get MSI token for UAMI using user-specified client ID")
		}
		return token, nil
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
		token, err := c.imdsClient.GetMSIToken(ctx, clientID, aadResource)
		if err != nil {
			return "", fmt.Errorf("unable to get MSI token from IMDS: %w", err)
		}
		return token, nil
	}

	c.logger.Info("retrieving SP access token from AAD...")
	if azureConfig.ClientSecret == "" {
		return "", fmt.Errorf("cannot retrieve SP token from AAD: azure.json missing clientSecret")
	}
	if azureConfig.TenantID == "" {
		return "", fmt.Errorf("cannot retrieve SP token from AAD: azure.json missing tenantId")
	}
	token, err := c.aadClient.GetToken(ctx, azureConfig, aadResource)
	if err != nil {
		return "", fmt.Errorf("unable to get SPN token from AAD: %w", err)
	}
	return token, nil

}
