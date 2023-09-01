// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package client

//go:generate ../../bin/mockgen -copyright_file=../../hack/copyright_header.txt -destination=./mocks/mock_imds.go -package=mocks github.com/Azure/aks-tls-bootstrap-client/pkg/client ImdsClient

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/Azure/aks-tls-bootstrap-client/pkg/datamodel"
	"github.com/sirupsen/logrus"
)

type ImdsClient interface {
	GetMSIToken(ctx context.Context, imdsURL, clientID string) (*datamodel.TokenResponseJSON, error)
	GetInstanceData(ctx context.Context, imdsURL string) (*datamodel.VmssInstanceData, error)
	GetAttestedData(ctx context.Context, imdsURL, nonce string) (*datamodel.VmssAttestedData, error)
}

func NewImdsClient(logger *logrus.Logger) ImdsClient {
	return &imdsClientImpl{
		logger: logger,
	}
}

type imdsClientImpl struct {
	logger *logrus.Logger
}

func (c *imdsClientImpl) GetMSIToken(ctx context.Context, imdsURL, clientID string) (*datamodel.TokenResponseJSON, error) {
	// TODO(cameissner): modify so this works on all clouds later
	url := fmt.Sprintf("%s/metadata/identity/oauth2/token", imdsURL)
	queryParameters := map[string]string{
		"api-version": "2018-02-01",
		"resource":    "https://management.azure.com/",
	}
	if clientID != "" {
		queryParameters["client_id"] = clientID
	}

	data := &datamodel.TokenResponseJSON{}

	if err := getImdsData(ctx, c.logger, url, queryParameters, data); err != nil {
		return nil, fmt.Errorf("failed to retrieve IMDS MSI token: %w", err)
	}
	if data.Error != "" {
		return nil, fmt.Errorf("failed to retrieve IMDS MSI token (%s): %s", data.Error, data.ErrorDescription)
	}

	c.logger.WithField("accessToken", data.AccessToken).Debugf("retrieved access token")
	return data, nil
}

func (c *imdsClientImpl) GetInstanceData(ctx context.Context, imdsURL string) (*datamodel.VmssInstanceData, error) {
	url := fmt.Sprintf("%s/metadata/instance", imdsURL)
	queryParameters := map[string]string{
		"api-version": "2021-05-01",
		"format":      "json",
	}
	data := &datamodel.VmssInstanceData{}

	if err := getImdsData(ctx, c.logger, url, queryParameters, data); err != nil {
		return nil, fmt.Errorf("failed to retrieve IMDS instance data: %w", err)
	}

	return data, nil
}

func (c *imdsClientImpl) GetAttestedData(ctx context.Context, imdsURL, nonce string) (*datamodel.VmssAttestedData, error) {
	url := fmt.Sprintf("%s/metadata/attested/document", imdsURL)
	queryParameters := map[string]string{
		"api-version": "2021-05-01",
		"format":      "json",
		"nonce":       nonce,
	}

	data := &datamodel.VmssAttestedData{}
	if err := getImdsData(ctx, c.logger, url, queryParameters, data); err != nil {
		return nil, fmt.Errorf("failed to retrieve IMDS attested data: %w", err)
	}

	return data, nil
}

func getImdsData(ctx context.Context, logger *logrus.Logger, url string, queryParameters map[string]string, responseObject interface{}) error {
	client := http.Client{Transport: &http.Transport{Proxy: nil}}

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("failed to initialize HTTP request: %w", err)
	}

	request.Header.Add("Metadata", "True")

	query := request.URL.Query()
	for key := range queryParameters {
		query.Add(key, queryParameters[key])
	}
	request.URL.RawQuery = query.Encode()

	response, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("failed to retrieve IMDS data: %w", err)
	}

	defer response.Body.Close()
	responseBody, err := io.ReadAll(response.Body)
	if err != nil {
		return fmt.Errorf("failed to read IMDS response body: %w", err)
	}

	logger.WithField("responseBody", string(responseBody)).Debug("received IMDS reply")

	if err = json.Unmarshal(responseBody, responseObject); err != nil {
		return fmt.Errorf("failed to unmarshal IMDS data: %w", err)
	}

	return nil
}
