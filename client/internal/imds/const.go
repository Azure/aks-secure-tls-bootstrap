// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package imds

const (
	imdsURL              = "http://169.254.169.254"
	tokenEndpoint        = "metadata/identity/oauth2/token"
	instanceDataEndpoint = "metadata/instance"
	attestedDataEndpoint = "metadata/attested/document"
)

const (
	apiVersionParameterKey = "api-version"
	formatParameterKey     = "format"
)

const (
	metadataHeaderKey = "Metadata"
)

const (
	// https://learn.microsoft.com/en-us/azure/virtual-machines/instance-metadata-service#supported-api-versions
	apiVersion = "2023-07-01"
)
