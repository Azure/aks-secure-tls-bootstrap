// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package cloud

// ProviderConfig represents the fields we need from the azure.json
// file present on all AKS nodes.
type ProviderConfig struct {
	CloudName              string `json:"cloud"`
	ClientID               string `json:"aadClientId,omitempty"`
	ClientSecret           string `json:"aadClientSecret,omitempty"`
	TenantID               string `json:"tenantId,omitempty"`
	UserAssignedIdentityID string `json:"userAssignedIdentityID,omitempty"`
}
