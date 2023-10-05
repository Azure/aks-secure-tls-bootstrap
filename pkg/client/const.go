// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package client

import "time"

const (
	// This is used to retrieve cluster details (such as cluster CA details + apiserver hostname) from the environment.
	kubernetesExecInfoVarName = "KUBERNETES_EXEC_INFO"
	// The default azure config path on Linux systems, used to infer identity-related details.
	defaultLinuxAzureJSONPath = "/etc/kubernetes/azure.json"
	// The default azure config path on Windows systems.
	defaultWindowsAzureJSONPath = "c:\\k\\azure.json"
	// The clientId used to denote Managed Service Identities (MSI).
	managedServiceIdentity = "msi"
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

	// AAD-related consts
	// The template used to specify the AAD login authority in public cloud environments.
	microsoftLoginAuthorityTemplate = "https://login.microsoftonline.com/%s"
	// Max delay for retrying requests to AAD.
	getAadTokenMaxDelay = 10 * time.Second
	// Max number of retries for requests to AAD.
	getAadTokenMaxRetries = 10

	// IMDS-related consts
	// The URL used to connect to IMDS.
	baseImdsURL = "http://169.254.169.254"
	// Used to specify "Metadata" header in IMDS requests.
	metadataHeaderKey = "Metadata"
	// API version used for calling the MSI token endpoin of IMDS.
	imdsMSITokenAPIVersion = "2018-02-01"
	// API version used for calling the instance data endpoint of IMDS
	imdsInstanceDataAPIVersion = "2021-05-01"
	// API version used for calling the attested data endpoint of IMDS.
	imdsAttestedDataAPIVersion = "2021-05-01"
	// Max delay for retrying requests to IMDS.
	imdsRequestMaxDelay = 10 * time.Second
	// Max number of retries for requests to IMDS.
	imdsRequestMaxRetries = 10
)
