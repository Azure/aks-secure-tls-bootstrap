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
	ClientID               string `json:"aadClientId,omitempty"`
	ClientSecret           string `json:"aadClientSecret,omitempty"`
	TenantID               string `json:"tenantId,omitempty"`
	UserAssignedIdentityID string `json:"userAssignedIdentityID,omitempty"`
}

// ExecCredential represents cluster-related data supplied to the client plugin
// by kubelet when invoked for generating bootstrap tokens.
type ExecCredential struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Spec       struct {
		Cluster struct {
			CertificateAuthorityData string      `json:"certificate-authority-data,omitempty"`
			Config                   interface{} `json:"config,omitempty"`
			InsecureSkipTLSVerify    bool        `json:"insecure-skip-tls-verify,omitempty"`
			ProxyURL                 string      `json:"proxy-url,omitempty"`
			Server                   string      `json:"server,omitempty"`
			TLSServerName            string      `json:"tls-server-name,omitempty"`
		} `json:"cluster,omitempty"`
		Interactive bool `json:"interactive,omitempty"`
	} `json:"spec,omitempty"`
	Status ExecCredentialStatus `json:"status,omitempty"`
}

type ExecCredentialStatus struct {
	ClientCertificateData string `json:"clientCertificateData,omitempty"`
	ClientKeyData         string `json:"clientKeyData,omitempty"`
	ExpirationTimestamp   string `json:"expirationTimestamp,omitempty"`
	Token                 string `json:"token,omitempty"`
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
	Encoding  string `json:"encoding,omitempty"`
	Signature string `json:"signature,omitempty"`
}
