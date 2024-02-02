// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package client

import (
	"fmt"

	"github.com/Azure/aks-secure-tls-bootstrap/client/pkg/datamodel"
	"github.com/Azure/aks-secure-tls-bootstrap/client/pkg/util"
)

const (
	azureConfigPathLinux   = "/etc/kubernetes/azure.json"
	azureConfigPathWindows = "c:\\k\\azure.json"
)

func loadAzureConfig(fs util.FS) (*datamodel.AzureConfig, error) {
	var (
		azureConfig = &datamodel.AzureConfig{}
		err         error
	)
	if util.IsWindows() {
		err = util.LoadJSONFromPath(fs, azureConfigPathWindows, azureConfig)
	} else {
		err = util.LoadJSONFromPath(fs, azureConfigPathLinux, azureConfig)
	}
	if err != nil {
		return nil, fmt.Errorf("unable to load azure config: %w", err)
	}
	return azureConfig, nil
}
