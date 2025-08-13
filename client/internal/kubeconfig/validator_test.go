// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package kubeconfig

import (
	"fmt"
	"testing"
	"time"

	"github.com/Azure/aks-secure-tls-bootstrap/client/internal/log"
	"github.com/Azure/aks-secure-tls-bootstrap/client/internal/testutil"
	"github.com/stretchr/testify/assert"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	fakediscovery "k8s.io/client-go/discovery/fake"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	restclient "k8s.io/client-go/rest"
	clientgotesting "k8s.io/client-go/testing"
)

func TestNewValidator(t *testing.T) {
	v := NewValidator()
	assert.NotNil(t, v)

	vv, ok := v.(*validator)
	assert.True(t, ok)
	assert.NotNil(t, vv.clientConfigLoader)
	assert.NotNil(t, vv.clientsetLoader)
}

func TestValidateKubeconfig(t *testing.T) {
	validCertPEM, validKeyPEM, err := testutil.GenerateCertPEM(testutil.CertTemplate{
		CommonName:   "cn",
		Organization: "org",
		Expiration:   time.Now().Add(time.Hour),
	})
	assert.NoError(t, err)

	expiredCertPEM, expiredKeyPEM, err := testutil.GenerateCertPEM(testutil.CertTemplate{
		CommonName:   "cn",
		Organization: "org",
		Expiration:   time.Now().Add(-1 * time.Hour),
	})
	assert.NoError(t, err)

	otherValidKeyPEM, err := testutil.GeneratePrivateKeyPEM()
	assert.NoError(t, err)

	tests := []struct {
		name         string
		setupFunc    func(v *validator)
		expectedErrs []string
	}{
		{
			name: "kubeconfig is valid",
			setupFunc: func(v *validator) {
				v.clientConfigLoader = func(kubeconfigPath string) (*restclient.Config, error) {
					return &restclient.Config{
						Host: "https://controlplane.azmk8s.io",
						TLSClientConfig: restclient.TLSClientConfig{
							CertData: validCertPEM,
							KeyData:  validKeyPEM,
						},
					}, nil
				}
			},
			expectedErrs: []string{},
		},
		{
			name: "the REST config cannot be loaded from the specified kubeconfig",
			setupFunc: func(v *validator) {
				v.clientConfigLoader = func(kubeconfigPath string) (*restclient.Config, error) {
					return nil, fmt.Errorf("unable to load kubeconfig")
				}
			},
			expectedErrs: []string{
				"failed to create REST client config from kubeconfig",
				"unable to load kubeconfig",
			},
		},
		{
			name: "cert data is empty",
			setupFunc: func(v *validator) {
				v.clientConfigLoader = func(kubeconfigPath string) (*restclient.Config, error) {
					return &restclient.Config{}, nil
				}
			},
			expectedErrs: []string{
				"failed to validate client config contents: unable to load TLS certificates from existing kubeconfig",
				"does not contain any valid RSA or ECDSA certificates",
			},
		},
		{
			name: "specified private key is not compatible with specified certificate",
			setupFunc: func(v *validator) {
				v.clientConfigLoader = func(kubeconfigPath string) (*restclient.Config, error) {
					return &restclient.Config{
						Host: "https://controlplane.azmk8s.io",
						TLSClientConfig: restclient.TLSClientConfig{
							CertData: validCertPEM,
							KeyData:  otherValidKeyPEM,
						},
					}, nil
				}
			},
			expectedErrs: []string{
				"private key does not match public key",
			},
		},
		{
			name: "certificate has expired",
			setupFunc: func(v *validator) {
				v.clientConfigLoader = func(kubeconfigPath string) (*restclient.Config, error) {
					return &restclient.Config{
						Host: "https://controlplane.azmk8s.io",
						TLSClientConfig: restclient.TLSClientConfig{
							CertData: expiredCertPEM,
							KeyData:  expiredKeyPEM,
						},
					}, nil
				}
			},
			expectedErrs: []string{
				"some part of the existing kubeconfig certificate has expired",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := log.NewTestContext()
			v := new(validator)
			tt.setupFunc(v)

			err := v.Validate(ctx, "path", false)
			if len(tt.expectedErrs) > 0 {
				assert.Error(t, err)
				for _, expectedErr := range tt.expectedErrs {
					assert.ErrorContains(t, err, expectedErr)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestEnsureAuthorizedClient(t *testing.T) {
	tests := []struct {
		name         string
		setupFunc    func(v *validator, clientset *fake.Clientset)
		expectedErrs []string
	}{
		{
			name: "clientset cannot be loaded from client REST config",
			setupFunc: func(v *validator, clientset *fake.Clientset) {
				v.clientsetLoader = func(clientConfig *restclient.Config) (kubernetes.Interface, error) {
					return nil, fmt.Errorf("bad rest config")
				}
			},
			expectedErrs: []string{
				"failed to create clientset from REST client config",
				"bad rest config",
			},
		},
		{
			name: "kubeconfig contains valid cert and key but is still unauthorized",
			setupFunc: func(v *validator, clientset *fake.Clientset) {
				clientset.Discovery().(*fakediscovery.FakeDiscovery).
					PrependReactor("get", "version", func(action clientgotesting.Action) (handled bool, ret runtime.Object, err error) {
						return true, nil, errors.NewUnauthorized("client certificate signed by unknown authority")
					})
			},
			expectedErrs: []string{
				"cannot make authorized request to list server version",
				"client certificate signed by unknown authority",
			},
		},
		{
			name: "kubeconfig contains valid cert and key but server list returns unknown error",
			setupFunc: func(v *validator, clientset *fake.Clientset) {
				clientset.Discovery().(*fakediscovery.FakeDiscovery).
					PrependReactor("get", "version", func(action clientgotesting.Action) (handled bool, ret runtime.Object, err error) {
						return true, nil, errors.NewInternalError(fmt.Errorf("server unavailable"))
					})
			},
			expectedErrs: []string{
				"encountered an unexpected error when attempting to request server version info",
				"server unavailable",
			},
		},
		{
			name:         "kubeconfig contains valid cert and key and can make an authorized request to the server",
			setupFunc:    func(v *validator, clientset *fake.Clientset) {},
			expectedErrs: []string{},
		},
	}

	validCertPEM, validKeyPEM, err := testutil.GenerateCertPEM(testutil.CertTemplate{
		CommonName:   "cn",
		Organization: "org",
		Expiration:   time.Now().Add(time.Hour),
	})
	assert.NoError(t, err)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := log.NewTestContext()
			v := new(validator)

			clientset := fake.NewSimpleClientset()
			v.clientConfigLoader = func(kubeconfigPath string) (*restclient.Config, error) {
				return &restclient.Config{
					Host: "https://controlplane.azmk8s.io",
					TLSClientConfig: restclient.TLSClientConfig{
						CertData: validCertPEM,
						KeyData:  validKeyPEM,
					},
				}, nil
			}

			v.clientsetLoader = func(clientConfig *restclient.Config) (kubernetes.Interface, error) {
				return clientset, nil
			}

			tt.setupFunc(v, clientset)
			err := v.Validate(ctx, "path", true)

			if len(tt.expectedErrs) > 0 {
				assert.Error(t, err)
				for _, expectedErr := range tt.expectedErrs {
					assert.ErrorContains(t, err, expectedErr)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
