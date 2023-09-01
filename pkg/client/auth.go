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

func (c *tlsBootstrapClientImpl) getAuthToken(ctx context.Context, clientID string, azureConfig *datamodel.KubeletAzureJSON) (string, error) {
	if clientID == "" {
		if azureConfig == nil {
			return "", fmt.Errorf("clientId is missing and supplied azureConfig is nil")
		}
		if azureConfig.ClientID == managedServiceIdentity {
			c.logger.Debug("resolving clientId to userAssignedIdentityId from azure.json")
			clientID = azureConfig.UserAssignedIdentityID
		}
	}

	if clientID != "" || azureConfig.ClientID == managedServiceIdentity {
		c.logger.Info("retrieving MSI access token from IMDS")
		msiToken, err := c.imdsClient.GetMSIToken(ctx, baseImdsURL, clientID)
		if err != nil {
			return "", err
		}
		return msiToken.AccessToken, nil
	}

	if azureConfig.ClientID == "" {
		return "", fmt.Errorf("cannot retrieve SP token from AAD: azure.json missing clientId")
	}

	if azureConfig.ClientSecret == "" {
		return "", fmt.Errorf("cannot retrieve SP token from AAD: azure.json missing clientSecret")
	}

	if azureConfig.TenantID == "" {
		return "", fmt.Errorf("cannot retrieve SP token from AAD: azure.json missing tenantId")
	}

	c.logger.Info("retrieving SP access token from AAD")
	spToken, err := c.aadClient.GetAadToken(
		ctx,
		azureConfig.ClientID,
		azureConfig.ClientSecret,
		azureConfig.TenantID,
		nil,
	)
	if err != nil {
		return "", err
	}
	return spToken, nil
}

func loadAzureJSON() (*datamodel.KubeletAzureJSON, error) {
	if isWindows() {
		return loadAzureJSONFromPath(defaultWindowsAzureJSONPath)
	}
	return loadAzureJSONFromPath(defaultLinuxAzureJSONPath)
}

func loadAzureJSONFromPath(path string) (*datamodel.KubeletAzureJSON, error) {
	azureJSON, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to parse %s", path)
	}

	azureConfig := &datamodel.KubeletAzureJSON{}
	if err = json.Unmarshal(azureJSON, azureConfig); err != nil {
		return nil, fmt.Errorf("failed to unmarshal %s", path)
	}

	return azureConfig, nil
}
