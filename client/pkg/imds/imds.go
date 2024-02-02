// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package imds

//go:generate ../../../bin/mockgen -copyright_file=../../../hack/copyright_header.txt -destination=./mocks/mock_imds.go -package=mocks github.com/Azure/aks-secure-tls-bootstrap/client/pkg/imds Client

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/Azure/aks-secure-tls-bootstrap/client/pkg/datamodel"
	"github.com/hashicorp/go-retryablehttp"
	"go.uber.org/zap"
)

type Client interface {
	GetMSIToken(ctx context.Context, clientID, aadResource string) (string, error)
	GetInstanceData(ctx context.Context) (*datamodel.VMSSInstanceData, error)
	GetAttestedData(ctx context.Context, nonce string) (*datamodel.VMSSAttestedData, error)
}

type ClientImpl struct {
	baseURL    string
	httpClient *retryablehttp.Client
	logger     *zap.Logger
}

var _ Client = &ClientImpl{}

func NewClient(logger *zap.Logger) *ClientImpl {
	httpClient := retryablehttp.NewClient()
	httpClient.HTTPClient.Timeout = defaultIMDSRequestTimeout
	return &ClientImpl{
		baseURL:    imdsURL,
		httpClient: httpClient,
		logger:     logger,
	}
}

func (c *ClientImpl) GetMSIToken(ctx context.Context, clientID, aadResource string) (string, error) {
	url := fmt.Sprintf("%s/%s", c.baseURL, msiTokenEndpoint)
	c.logger.Info("calling IMDS MSI token endpoint", zap.String("url", url))

	queryParameters := map[string]string{
		apiVersionHeaderKey: msiTokenAPIVersion,
		resourceHeaderKey:   aadResource,
	}
	if clientID != "" {
		queryParameters[clientIDHeaderKey] = clientID
	}

	tokenResponse := &datamodel.AADTokenResponse{}
	if err := c.callIMDS(ctx, url, queryParameters, tokenResponse); err != nil {
		return "", fmt.Errorf("failed to retrieve MSI token: %w", err)
	}
	if tokenResponse.Error != "" {
		return "", fmt.Errorf("failed to retrieve MSI token: %s: %s", tokenResponse.Error, tokenResponse.ErrorDescription)
	}

	return tokenResponse.AccessToken, nil
}

func (c *ClientImpl) GetInstanceData(ctx context.Context) (*datamodel.VMSSInstanceData, error) {
	url := fmt.Sprintf("%s/%s", c.baseURL, instanceDataEndpoint)
	c.logger.Info("calling IMDS instance data endpoint", zap.String("url", url))

	queryParameters := map[string]string{
		apiVersionHeaderKey: instanceDataAPIVersion,
		formatHeaderKey:     formatJSON,
	}
	data := &datamodel.VMSSInstanceData{}

	if err := c.callIMDS(ctx, url, queryParameters, data); err != nil {
		return nil, fmt.Errorf("failed to retrieve IMDS instance data: %w", err)
	}

	return data, nil
}

func (c *ClientImpl) GetAttestedData(ctx context.Context, nonce string) (*datamodel.VMSSAttestedData, error) {
	url := fmt.Sprintf("%s/%s", c.baseURL, attestedDataEndpoint)
	c.logger.Info("calling IMDS attested data endpoint", zap.String("url", url))

	queryParameters := map[string]string{
		apiVersionHeaderKey: attestedDataAPIVersion,
		formatHeaderKey:     formatJSON,
		nonceHeaderKey:      nonce,
	}

	data := &datamodel.VMSSAttestedData{}
	if err := c.callIMDS(ctx, url, queryParameters, data); err != nil {
		return nil, fmt.Errorf("failed to retrieve IMDS attested data: %w", err)
	}

	return data, nil
}

func (c *ClientImpl) callIMDS(ctx context.Context, url string, queryParameters map[string]string, responseObject interface{}) error {
	req, err := retryablehttp.NewRequestWithContext(ctx, http.MethodGet, url, nil)
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
