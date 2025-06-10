// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package imds

//go:generate ../../bin/mockgen -copyright_file=../../../hack/copyright_header.txt -destination=./mocks/mock_imds.go -package=mocks github.com/Azure/aks-secure-tls-bootstrap/client/internal/imds Client

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	internalhttp "github.com/Azure/aks-secure-tls-bootstrap/client/internal/http"
	"go.uber.org/zap"
)

type Client interface {
	GetInstanceData(ctx context.Context) (*VMInstanceData, error)
	GetAttestedData(ctx context.Context) (*VMAttestedData, error)
}

type client struct {
	baseURL    string
	httpClient *http.Client
	logger     *zap.Logger
}

var _ Client = (*client)(nil)

func NewClient(logger *zap.Logger) Client {
	return &client{
		baseURL:    imdsURL,
		httpClient: internalhttp.NewClient(logger),
		logger:     logger,
	}
}

func (c *client) GetInstanceData(ctx context.Context) (*VMInstanceData, error) {
	url := fmt.Sprintf("%s/%s", c.baseURL, instanceDataEndpoint)
	c.logger.Info("calling IMDS instance data endpoint", zap.String("url", url))

	params := getCommonParameters()

	instanceData := new(VMInstanceData)
	if err := c.callIMDS(ctx, url, params, instanceData); err != nil {
		return nil, fmt.Errorf("failed to retrieve IMDS instance data: %w", err)
	}

	return instanceData, nil
}

func (c *client) GetAttestedData(ctx context.Context) (*VMAttestedData, error) {
	url := fmt.Sprintf("%s/%s", c.baseURL, attestedDataEndpoint)
	c.logger.Info("calling IMDS attested data endpoint", zap.String("url", url))

	params := getCommonParameters()

	attestedData := new(VMAttestedData)
	if err := c.callIMDS(ctx, url, params, attestedData); err != nil {
		return nil, fmt.Errorf("failed to retrieve IMDS attested data: %w", err)
	}

	return attestedData, nil
}

func (c *client) callIMDS(ctx context.Context, url string, queryParameters map[string]string, responseObject interface{}) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("failed to construct new HTTP request to IMDS: %w", err)
	}
	req.Header.Add(metadataHeaderKey, "True")

	query := req.URL.Query()
	for key := range queryParameters {
		query.Add(key, queryParameters[key])
	}
	req.URL.RawQuery = query.Encode()

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to do HTTP request to IMDS: %w", err)
	}
	if resp != nil && resp.Body != nil {
		defer resp.Body.Close()
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read IMDS response body: %w", err)
	}

	if err := json.Unmarshal(body, responseObject); err != nil {
		return fmt.Errorf("failed to unmarshal IMDS data: %w", err)
	}

	return nil
}

func getCommonParameters() map[string]string {
	return map[string]string{
		apiVersionParameterKey: apiVersion,
		formatParameterKey:     "json",
	}
}
