// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package kubeconfig

//go:generate ../../bin/mockgen -copyright_file=../../../hack/copyright_header.txt -destination=./mocks/mock_validator.go -package=mocks github.com/Azure/aks-secure-tls-bootstrap/client/pkg/kubeconfig Validator

import (
	"fmt"
	"os"
	"time"

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/client-go/kubernetes"
	restclient "k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/transport"
	certutil "k8s.io/client-go/util/cert"
)

// kubeconfigLoader provides an interface for loading and unmarshaling a kubeconfig YAML from disk
// and returning the corresponding REST client config.
type clientConfigLoaderFunc func(kubeconfigPath string) (*restclient.Config, error)

// clientsetLoaderFunc provides an interface for creating a kubernetes.Interface
// from a specified REST client config.
type clientsetLoaderFunc func(clientConfig *restclient.Config) (kubernetes.Interface, error)

type Validator interface {
	Validate(kubeconfigPath string, ensureAuthorizedClient bool) error
}

type validator struct {
	clientConfigLoader clientConfigLoaderFunc
	clientsetLoader    clientsetLoaderFunc
}

var _ Validator = (*validator)(nil)

func NewValidator() Validator {
	return &validator{
		clientConfigLoader: func(kubeconfigPath string) (*restclient.Config, error) {
			if _, err := os.Stat(kubeconfigPath); err != nil {
				return nil, fmt.Errorf("failed to read specified kubeconfig: %w", err)
			}
			// Load structured kubeconfig data from the given path.
			loader := &clientcmd.ClientConfigLoadingRules{ExplicitPath: kubeconfigPath}
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
		},
		clientsetLoader: func(clientConfig *restclient.Config) (kubernetes.Interface, error) {
			return kubernetes.NewForConfig(clientConfig)
		},
	}
}

func (v *validator) Validate(kubeconfigPath string, ensureAuthorizedClient bool) error {
	clientConfig, err := v.clientConfigLoader(kubeconfigPath)
	if err != nil {
		return fmt.Errorf("failed to create REST client config from kubeconfig: %w", err)
	}
	if err := ensureClientConfig(clientConfig); err != nil {
		return fmt.Errorf("failed to ensure client config contents: %w", err)
	}
	if ensureAuthorizedClient {
		clientset, err := v.clientsetLoader(clientConfig)
		if err != nil {
			return fmt.Errorf("failed to create clientset from client REST config: %w", err)
		}
		if err := ensureAuthorizedClientset(clientset); err != nil {
			return fmt.Errorf("failed to ensure client config authorization: %w", err)
		}
	}
	return nil
}

// ensureClientConfig returns a nil error iff the specified rest config contains a valid, unexpired client certificate.
// Note that this function does NOT check whether the certificate signer is valid.
func ensureClientConfig(clientConfig *restclient.Config) error {
	transportConfig, err := clientConfig.TransportConfig()
	if err != nil {
		return fmt.Errorf("unable to load transport configuration from existing kubeconfig: %w", err)
	}
	if _, err := transport.TLSConfigFor(transportConfig); err != nil {
		return fmt.Errorf("unable to load TLS configuration from existing kubeconfig: %w", err)
	}
	certs, err := certutil.ParseCertsPEM(transportConfig.TLS.CertData)
	if err != nil {
		return fmt.Errorf("unable to load TLS certificates from existing kubeconfig: %w", err)
	}
	if len(certs) == 0 {
		return fmt.Errorf("unable to read TLS certificates from existing kubeconfig: %w", err)
	}
	now := time.Now()
	for _, cert := range certs {
		if now.After(cert.NotAfter) {
			return fmt.Errorf("some part of the existing kubeconfig certificate has expired")
		}
	}
	return nil
}

func ensureAuthorizedClientset(clientset kubernetes.Interface) error {
	_, err := clientset.Discovery().ServerVersion()
	switch {
	case err == nil:
		return nil
	case errors.IsUnauthorized(err):
		return fmt.Errorf("cannot make authorized request to list server version: %w", err)
	default:
		// can potentially retry in these cases
		return fmt.Errorf("encountered an unexpected error when attempting to request server version info: %w", err)
	}
}
