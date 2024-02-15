// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package kubeconfig

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

const (
	blockTypeECPrivateKey = "EC PRIVATE KEY"
)

type GenerateOpts struct {
	APIServerFQDN string
	ClusterCAData []byte
}

func GenerateForCertAndKey(certPEM []byte, privateKey *ecdsa.PrivateKey, opts *GenerateOpts) (*clientcmdapi.Config, error) {
	keyDER, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("unable to marshal EC private key during kubeconfig generation: %w", err)
	}
	block := &pem.Block{
		Type:  blockTypeECPrivateKey,
		Bytes: keyDER,
	}
	keyPEM := pem.EncodeToMemory(block)

	kubeconfigData := &clientcmdapi.Config{
		Clusters: map[string]*clientcmdapi.Cluster{"default-cluster": {
			Server:                   opts.APIServerFQDN,
			CertificateAuthorityData: opts.ClusterCAData,
		}},
		// Define auth based on the obtained client cert.
		AuthInfos: map[string]*clientcmdapi.AuthInfo{"default-auth": {
			ClientCertificateData: certPEM,
			ClientKeyData:         keyPEM,
		}},
		// Define a context that connects the auth info and cluster, and set it as the default
		Contexts: map[string]*clientcmdapi.Context{"default-context": {
			Cluster:  "default-cluster",
			AuthInfo: "default-auth",
		}},
		CurrentContext: "default-context",
	}

	return kubeconfigData, nil
}
