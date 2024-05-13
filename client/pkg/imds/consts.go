// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package imds

import "time"

// IMDS URL and relevant endpoints.
const (
	imdsURL              = "http://169.254.169.254"
	msiTokenEndpoint     = "metadata/identity/oauth2/token"
	instanceDataEndpoint = "metadata/instance"
	attestedDataEndpoint = "metadata/attested/document"

	// API version used for calling the MSI token endpoin of IMDS.
	msiTokenAPIVersion = "2018-02-01"
	// API version used for calling the instance data endpoint of IMDS
	instanceDataAPIVersion = "2021-05-01"
	// API version used for calling the attested data endpoint of IMDS.
	attestedDataAPIVersion = "2021-05-01"
)

const (
	// Used to specify JSON format within IMDS requests.
	formatJSON = "json"
	// Used to specift API version as query parameter in IMDS requests
	apiVersionHeaderKey = "api-version"
	// Used to specify format type header in requests to IMDS.
	formatHeaderKey = "format"
	// Used to specify resource header in requests to IMDS MSI token endpoint.
	resourceHeaderKey = "resource"
	// Used to specify client ID in requests to IMDS MSI token endpoint.
	clientIDHeaderKey = "client_id"
	// Used to specify nonce request header in requests to IMDS attested data endpoint.
	nonceHeaderKey = "nonce"
	// Used to specify "Metadata" header in IMDS requests.
	metadataHeaderKey = "Metadata"
	// Used to specify the user-agent header in IMDS requests.
	userAgentHeaderKey = "User-Agent"
)

const (
	defaultIMDSRequestTimeout = 10 * time.Second
)
