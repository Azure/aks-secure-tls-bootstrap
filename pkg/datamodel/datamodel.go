// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package datamodel

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

// AADTokenClaims embeds the jwt.RegisteredClaims object, containg
// common registered JWT claims such as 'exp', 'aud', 'iat', etc. It also
// contains the AAD-specific claims that we use in order to perform authz
type AADTokenClaims struct {
	AppID string `json:"appid"`
	Tid   string `json:"tid"`
	jwt.RegisteredClaims
}

// Valid is required to implement the jwt.Claims interface.
// Valid will perform basic validation of AAD-related claims, as well
// as call the Valid method on the embedded RegisteredClaims struct which contains
// common registered claims that mostly every JWT is expected to have in its payload
// (such as 'aud', 'exp', 'iat', etc.). AADTokenClaims must implement the jwt.Claims
// interface so we can delegate base-level claim validation to the jwt package on the server side.
func (c *AADTokenClaims) Valid() error {
	if c.AppID == "" {
		return fmt.Errorf("appid claim must be included and non-empty")
	}
	if c.Tid == "" {
		return fmt.Errorf("tid claim must be included and non-empty")
	}
	return c.RegisteredClaims.Valid()
}

// AADTokenResponse is used to unmarshal responses received from
// IMDS when retrieving MSI tokens for authentication.
type AADTokenResponse struct {
	AccessToken      string `json:"access_token"`
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

// BootstrapTokenRequest represents a request to generate a new
// unique TLS bootstrap token on the server-side.
type BootstrapTokenRequest struct {
	Nonce      string
	Expiration time.Time
	ResourceID string
}

// AttestedData represents the set of fields we need when decoding
// and unmarshaliong attested data blobs received from IMDS.
type AttestedData struct {
	Nonce string `json:",omitempty"`
	VMID  string `json:"vmId,omitempty"`
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
	Status struct {
		ClientCertificateData string `json:"clientCertificateData,omitempty"`
		ClientKeyData         string `json:"clientKeyData,omitempty"`
		ExpirationTimestamp   string `json:"expirationTimestamp,omitempty"`
		Token                 string `json:"token,omitempty"`
	} `json:"status,omitempty"`
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
