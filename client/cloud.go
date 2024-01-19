// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package client

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Azure/aks-secure-tls-bootstrap/client/pkg/datamodel"
	"github.com/Azure/go-autorest/autorest/azure"
)

const (
	azureConfigPathLinux         = "/etc/kubernetes/azure.json"
	azureConfigPathWindows       = "c:\\k\\azure.json"
	customCloudConfigPathLinux   = "/etc/kubernetes/akscustom.json"
	customCloudConfigPathWindows = "c:\\k\\azurestackcloud.json"

	azurePublicCloud = "AzurePublicCloud"
	azureUSGovCloud  = "AzureUSGovernmentCloud"
	azureChinaCloud  = "AzureChinaCloud"
)

func getAADAuthorityURL(reader fileReader, azureConfig *datamodel.AzureConfig) (string, error) {
	cloudName := azureConfig.Cloud

	if strings.EqualFold(cloudName, azurePublicCloud) || strings.EqualFold(cloudName, azureUSGovCloud) || strings.EqualFold(cloudName, azureChinaCloud) {
		env, err := azure.EnvironmentFromName(cloudName)
		if err != nil {
			return "", fmt.Errorf("unable to determine cloud environment config from cloud name %s: %w", cloudName, err)
		}
		return env.ActiveDirectoryEndpoint, nil
	}

	// azure.EnvironmnetFromName does something similar for stack, but that relies on AZURE_ENVIRONMENT_FILENAME being set
	// which isn't always the case on Windows.
	var (
		customEnv = &azure.Environment{}
		err       error
	)
	if isWindows() {
		err = loadJSONFromPath(reader, customCloudConfigPathWindows, customEnv)
	} else {
		err = loadJSONFromPath(reader, customCloudConfigPathLinux, customEnv)
	}
	if err != nil {
		return "", fmt.Errorf("unable to load custom cloud environment config: %w", err)
	}

	return customEnv.ActiveDirectoryEndpoint, nil
}

func (c *tlsBootstrapClientImpl) loadAzureConfig() error {
	var (
		azureConfig = &datamodel.AzureConfig{}
		err         error
	)
	if isWindows() {
		err = loadJSONFromPath(c.reader, azureConfigPathWindows, azureConfig)
	} else {
		err = loadJSONFromPath(c.reader, azureConfigPathLinux, azureConfig)
	}
	if err != nil {
		return fmt.Errorf("unable to load azure config: %w", err)
	}
	c.azureConfig = azureConfig
	return nil
}

func loadJSONFromPath(reader fileReader, path string, out interface{}) error {
	jsonBytes, err := reader.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to parse %s: %w", path, err)
	}
	if err = json.Unmarshal(jsonBytes, out); err != nil {
		return fmt.Errorf("failed to unmarshal %s: %w", path, err)
	}
	return nil
}
