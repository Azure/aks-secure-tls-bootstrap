// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package cloud

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	azcloud "github.com/Azure/azure-sdk-for-go/sdk/azcore/cloud"
	"github.com/Azure/go-autorest/autorest/azure"
	"github.com/stretchr/testify/assert"
)

func TestGetCloudConfig(t *testing.T) {
	cases := []struct {
		name          string
		cloudName     string
		expected      azcloud.Configuration
		stackCloud    bool
		expectedError error
	}{
		{
			name:          "unrecognized cloud should return an error",
			cloudName:     "AzureUnrecognizedCloud",
			expectedError: errors.New(`unable to get azure environment from cloud name "AzureUnrecognizedCloud": autorest/azure: There is no cloud environment matching the name "AZUREUNRECOGNIZEDCLOUD"`),
		},
		{
			name:      "public cloud",
			cloudName: azure.PublicCloud.Name,
			expected: azcloud.Configuration{
				ActiveDirectoryAuthorityHost: azure.PublicCloud.ActiveDirectoryEndpoint,
				Services: map[azcloud.ServiceName]azcloud.ServiceConfiguration{
					azcloud.ResourceManager: {
						Audience: azure.PublicCloud.TokenAudience,
						Endpoint: azure.PublicCloud.ResourceManagerEndpoint,
					},
				},
			},
			expectedError: nil,
		},
		{
			name:      "usgov cloud",
			cloudName: azure.USGovernmentCloud.Name,
			expected: azcloud.Configuration{
				ActiveDirectoryAuthorityHost: azure.USGovernmentCloud.ActiveDirectoryEndpoint,
				Services: map[azcloud.ServiceName]azcloud.ServiceConfiguration{
					azcloud.ResourceManager: {
						Audience: azure.USGovernmentCloud.TokenAudience,
						Endpoint: azure.USGovernmentCloud.ResourceManagerEndpoint,
					},
				},
			},
			expectedError: nil,
		},
		{
			name:      "china cloud",
			cloudName: azure.ChinaCloud.Name,
			expected: azcloud.Configuration{
				ActiveDirectoryAuthorityHost: azure.ChinaCloud.ActiveDirectoryEndpoint,
				Services: map[azcloud.ServiceName]azcloud.ServiceConfiguration{
					azcloud.ResourceManager: {
						Audience: azure.ChinaCloud.TokenAudience,
						Endpoint: azure.ChinaCloud.ResourceManagerEndpoint,
					},
				},
			},
			expectedError: nil,
		},
		{
			name:       "stack cloud",
			cloudName:  "AzureStackCloud",
			stackCloud: true,
			expected: azcloud.Configuration{
				ActiveDirectoryAuthorityHost: "AzureStackAuthorityHostName",
				Services: map[azcloud.ServiceName]azcloud.ServiceConfiguration{
					azcloud.ResourceManager: {
						Audience: "AzureStackARMAudience",
						Endpoint: "AzureStackARMEndpoint",
					},
				},
			},
			expectedError: nil,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.stackCloud {
				stackEnvironmentFilePath := filepath.Join(t.TempDir(), "azenv.json")
				t.Setenv("AZURE_ENVIRONMENT_FILEPATH", stackEnvironmentFilePath)
				stackEnv := azure.Environment{
					ActiveDirectoryEndpoint: "AzureStackAuthorityHostName",
					TokenAudience:           "AzureStackARMAudience",
					ResourceManagerEndpoint: "AzureStackARMEndpoint",
				}
				stackEnvJSON, err := json.Marshal(stackEnv)
				assert.NoError(t, err)
				assert.NoError(t, os.WriteFile(stackEnvironmentFilePath, stackEnvJSON, os.ModePerm))
			}

			actual, err := GetCloudConfig(c.cloudName)
			if c.expectedError != nil {
				assert.EqualError(t, err, c.expectedError.Error())
			} else {
				assert.NoError(t, err)
				assert.Equal(t, c.expected, actual)
			}
		})
	}
}
