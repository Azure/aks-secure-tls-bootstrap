// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package cloud

import (
	"fmt"

	azcloud "github.com/Azure/azure-sdk-for-go/sdk/azcore/cloud"
	"github.com/Azure/go-autorest/autorest/azure"
)

// ProviderConfig encapsulates the required fields needed from the provided cloud provider config file,
// such as the azure.json file present on all AKS nodes.
type ProviderConfig struct {
	CloudName              string `json:"cloud"`
	ClientID               string `json:"aadClientId,omitempty"`
	ClientSecret           string `json:"aadClientSecret,omitempty"`
	TenantID               string `json:"tenantId,omitempty"`
	UserAssignedIdentityID string `json:"userAssignedIdentityID,omitempty"`
}

// GetCloudConfig returns the track2 cloud configuration for the specified cloud.
// If the cloud is unrecognized, and error will be returned.
func GetCloudConfig(cloudName string) (azcloud.Configuration, error) {
	// we need to use azure.EnvironmentFromName (track1) since track2 doesn't natively support
	// instantiating cloud configurations from static files. On AKS nodes running in custom/stack cloud environments,
	// we need to rely on a static file which defines the correct in-cloud service endpoints.
	azureEnvironment, err := azure.EnvironmentFromName(cloudName)
	if err != nil {
		return azcloud.Configuration{}, fmt.Errorf("unable to get azure environment from cloud name %q: %w", cloudName, err)
	}
	return azcloud.Configuration{
		ActiveDirectoryAuthorityHost: azureEnvironment.ActiveDirectoryEndpoint,
		Services: map[azcloud.ServiceName]azcloud.ServiceConfiguration{
			azcloud.ResourceManager: {
				Audience: azureEnvironment.TokenAudience,
				Endpoint: azureEnvironment.ResourceManagerEndpoint,
			},
		},
	}, nil
}
