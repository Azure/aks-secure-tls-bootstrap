// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package cloud

// ProviderConfig encapsulates the required fields needed from the provided cloud provider config file,
// such as the azure.json file present on all AKS nodes.
type ProviderConfig struct {
	CloudName              string `json:"cloud"`
	ClientID               string `json:"aadClientId,omitempty"`
	ClientSecret           string `json:"aadClientSecret,omitempty"`
	TenantID               string `json:"tenantId,omitempty"`
	UserAssignedIdentityID string `json:"userAssignedIdentityID,omitempty"`
}
