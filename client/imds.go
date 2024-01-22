// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package client

//go:generate ../bin/mockgen -copyright_file=../hack/copyright_header.txt -destination=./mocks/mock_imds.go -package=mocks github.com/Azure/aks-secure-tls-bootstrap/client ImdsClient

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/Azure/aks-secure-tls-bootstrap/client/pkg/datamodel"
	"go.uber.org/zap"

	"github.com/avast/retry-go/v4"
)

type ImdsClient interface {
	GetMSIToken(ctx context.Context, imdsURL, clientID, resource string) (*datamodel.AADTokenResponse, error)
	GetInstanceData(ctx context.Context, imdsURL string) (*datamodel.VMSSInstanceData, error)
	GetAttestedData(ctx context.Context, imdsURL, nonce string) (*datamodel.VMSSAttestedData, error)
}

func NewImdsClient(logger *zap.Logger) ImdsClient {
	return &imdsClientImpl{
		logger: logger,
	}
}

type imdsClientImpl struct {
	logger *zap.Logger
}

func (c *imdsClientImpl) GetMSIToken(ctx context.Context, imdsURL, clientID, resource string) (*datamodel.AADTokenResponse, error) {
	// TODO(cameissner): modify so this works on all clouds later
	url := fmt.Sprintf("%s/metadata/identity/oauth2/token", imdsURL)
	queryParameters := map[string]string{
		apiVersionHeaderKey: imdsMSITokenAPIVersion,
		resourceHeaderKey:   resource,
	}
	if clientID != "" {
		queryParameters[clientIDHeaderKey] = clientID
	}

	tokenResponse := &datamodel.AADTokenResponse{}
	if err := getImdsData(ctx, c.logger, url, queryParameters, tokenResponse); err != nil {
		return nil, fmt.Errorf("failed to retrieve MSI token: %w", err)
	}
	if tokenResponse.Error != "" {
		return nil, fmt.Errorf("failed to retrieve MSI token: %s: %s", tokenResponse.Error, tokenResponse.ErrorDescription)
	}

	c.logger.Debug("retrieved access token", zap.String("accessToken", tokenResponse.AccessToken))
	return tokenResponse, nil
}

func (c *imdsClientImpl) GetInstanceData(ctx context.Context, imdsURL string) (*datamodel.VMSSInstanceData, error) {
	url := fmt.Sprintf("%s/metadata/instance", imdsURL)
	queryParameters := map[string]string{
		apiVersionHeaderKey: imdsInstanceDataAPIVersion,
		formatHeaderKey:     formatJSON,
	}
	data := &datamodel.VMSSInstanceData{}

	if err := getImdsData(ctx, c.logger, url, queryParameters, data); err != nil {
		return nil, fmt.Errorf("failed to retrieve IMDS instance data: %w", err)
	}

	return data, nil
}

func (c *imdsClientImpl) GetAttestedData(ctx context.Context, imdsURL, nonce string) (*datamodel.VMSSAttestedData, error) {
	url := fmt.Sprintf("%s/metadata/attested/document", imdsURL)
	queryParameters := map[string]string{
		apiVersionHeaderKey: imdsAttestedDataAPIVersion,
		formatHeaderKey:     formatJSON,
		nonceHeaderKey:      nonce,
	}

	data := &datamodel.VMSSAttestedData{}
	if err := getImdsData(ctx, c.logger, url, queryParameters, data); err != nil {
		return nil, fmt.Errorf("failed to retrieve IMDS attested data: %w", err)
	}

	return data, nil
}

func getImdsData(ctx context.Context, logger *zap.Logger, url string, queryParameters map[string]string, responseObject interface{}) error {
	client := http.Client{
		Transport: &http.Transport{
			Proxy: nil,
		},
	}

	responseBody, err := retry.DoWithData(func() ([]byte, error) {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, retry.Unrecoverable(err)
		}
		request.Header.Add(metadataHeaderKey, "True")

		query := request.URL.Query()
		for key := range queryParameters {
			query.Add(key, queryParameters[key])
		}
		request.URL.RawQuery = query.Encode()

		response, err := client.Do(request)
		if err != nil {
			return nil, err
		}

		defer response.Body.Close()
		responseBody, err := io.ReadAll(response.Body)
		if err != nil {
			return nil, err
		}

		return responseBody, nil
	},
		retry.Context(ctx),
		retry.Attempts(imdsRequestMaxRetries),
		retry.MaxDelay(imdsRequestMaxDelay),
		retry.DelayType(retry.BackOffDelay))
	if err != nil {
		return fmt.Errorf("unable to retrieve data from IMDS: %w", err)
	}

	if err := json.Unmarshal(responseBody, responseObject); err != nil {
		return fmt.Errorf("failed to unmarshal IMDS data: %w", err)
	}

	return nil
}
