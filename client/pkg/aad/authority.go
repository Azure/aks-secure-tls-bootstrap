// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package aad

import (
	"fmt"
	"strings"

	"github.com/Azure/aks-secure-tls-bootstrap/client/pkg/datamodel"
	"github.com/Azure/aks-secure-tls-bootstrap/client/pkg/util"
	"github.com/Azure/go-autorest/autorest/azure"
)

func getAADAuthorityURL(fs util.FS, azureConfig *datamodel.AzureConfig) (string, error) {
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
	if util.IsWindows() {
		err = util.LoadJSONFromPath(fs, customCloudConfigPathWindows, customEnv)
	} else {
		err = util.LoadJSONFromPath(fs, customCloudConfigPathLinux, customEnv)
	}
	if err != nil {
		return "", fmt.Errorf("unable to load custom cloud environment config: %w", err)
	}

	return customEnv.ActiveDirectoryEndpoint, nil
}
