// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package datamodel

// AADTokenResponse is used to unmarshal responses received from
// IMDS when retrieving MSI tokens for authentication.
type AADTokenResponse struct {
	AccessToken      string `json:"access_token"`
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

// AzureConfig represents the fields we need from the azure.json
// file present on all AKS nodes.
type AzureConfig struct {
	Cloud                  string `json:"cloud"`
	ClientID               string `json:"aadClientId,omitempty"`
	ClientSecret           string `json:"aadClientSecret,omitempty"`
	TenantID               string `json:"tenantId,omitempty"`
	UserAssignedIdentityID string `json:"userAssignedIdentityID,omitempty"`
}

// Compute represents the compute-related fields we need from VMSS-related instance data.
type Compute struct {
	ResourceID string `json:"resourceId,omitempty"`
}

// VMSSInstanceData represents the top-level fields we need from VMSS-related
// instance data retrieved from IMDS.
type VMSSInstanceData struct {
	Compute Compute `json:"compute,omitempty"`
}

// VMSSAttestedData represents the fields we need the attested data
// response retrieved from IMDS.
type VMSSAttestedData struct {
	Signature string `json:"signature,omitempty"`
}
