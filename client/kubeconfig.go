// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package client

//go:generate ../../bin/mockgen -copyright_file=../../hack/copyright_header.txt -destination=./mocks/mock_kubeclient.go -package=mocks github.com/Azure/aks-secure-tls-bootstrap/client KubeClient

import (
	"fmt"
	"os"
	"time"

	"go.uber.org/zap"
	restclient "k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/transport"
	certutil "k8s.io/client-go/util/cert"
)

type KubeClient interface {
	IsKubeConfigStillValid(kubeConfigPath string) (bool, error)
}

func NewKubeClient(logger *zap.Logger) KubeClient {
	return &kubeClientImpl{
		logger: logger,
	}
}

type kubeClientImpl struct {
	logger *zap.Logger
}

func (c *kubeClientImpl) IsKubeConfigStillValid(kubeConfigPath string) (bool, error) {
	c.logger.Debug("checking if kubeconfig exists...")

	_, err := os.Stat(kubeConfigPath)
	if os.IsNotExist(err) {
		c.logger.Debug("kubeconfig does not exist. bootstrapping will continue")
		return false, nil
	}
	if err != nil {
		c.logger.Error("error reading existing bootstrap kubeconfig. bootstrapping will continue", zap.Error(err))
		return false, nil // not returning an error so bootstrap can continue
	}

	isValid, err := isClientConfigStillValid(kubeConfigPath, c.logger)
	if err != nil {
		return false, fmt.Errorf("unable to load kubeconfig: %v", err)
	}
	if isValid {
		c.logger.Debug("kubeconfig is valid. bootstrapping will not continue")
		return true, nil
	}

	c.logger.Debug("kubeconfig is invalid. bootstrapping will continue")
	return false, nil
}

// copied from https://github.com/kubernetes/kubernetes/blob/e45f5b089f770b1c8a1583f2792176bfe450bb47/pkg/kubelet/certificate/bootstrap/bootstrap.go#L231
// isClientConfigStillValid checks the provided kubeconfig to see if it has a valid
// client certificate. It returns true if the kubeconfig is valid, or an error if bootstrapping
// should stop immediately.
func isClientConfigStillValid(kubeconfigPath string, logger *zap.Logger) (bool, error) {
	bootstrapClientConfig, err := loadRESTClientConfig(kubeconfigPath)
	if err != nil {
		logger.Error("unable to read existing kubeconfig.")
		return false, err
	}
	transportConfig, err := bootstrapClientConfig.TransportConfig()
	if err != nil {
		logger.Error("unable to load transport configuration from existing kubeconfig.")
		return false, err
	}
	// has side effect of populating transport config data fields
	if _, err := transport.TLSConfigFor(transportConfig); err != nil {
		logger.Error("unable to load TLS configuration from existing kubeconfig.")
		return false, err
	}
	certs, err := certutil.ParseCertsPEM(transportConfig.TLS.CertData)
	if err != nil {
		logger.Error("unable to load TLS certificates from existing kubeconfig.")
		return false, err
	}
	if len(certs) == 0 {
		logger.Error("unable to read TLS certificates from existing kubeconfig.")
		return false, err
	}
	now := time.Now()
	for _, cert := range certs {
		if now.After(cert.NotAfter) {
			logger.Error("part of the existing kubeconfig certificate is expire.")
			return false, err
		}
	}
	return true, nil
}

// copied from https://github.com/kubernetes/kubernetes/blob/e45f5b089f770b1c8a1583f2792176bfe450bb47/pkg/kubelet/certificate/bootstrap/bootstrap.go#L212
func loadRESTClientConfig(kubeconfig string) (*restclient.Config, error) {
	// Load structured kubeconfig data from the given path.
	loader := &clientcmd.ClientConfigLoadingRules{ExplicitPath: kubeconfig}
	loadedConfig, err := loader.Load()
	if err != nil {
		return nil, err
	}
	// Flatten the loaded data to a particular restclient.Config based on the current context.
	return clientcmd.NewNonInteractiveClientConfig(
		*loadedConfig,
		loadedConfig.CurrentContext,
		&clientcmd.ConfigOverrides{},
		loader,
	).ClientConfig()
}
