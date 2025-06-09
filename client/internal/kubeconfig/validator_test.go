// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package kubeconfig

import (
	"fmt"
	"testing"
	"time"

	"github.com/Azure/aks-secure-tls-bootstrap/client/internal/testutil"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	fakediscovery "k8s.io/client-go/discovery/fake"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	restclient "k8s.io/client-go/rest"
	clientgotesting "k8s.io/client-go/testing"
)

func TestNewValidator(t *testing.T) {
	logger, _ := zap.NewDevelopment()

	v := NewValidator(logger)
	assert.NotNil(t, v)

	vv, ok := v.(*validator)
	assert.True(t, ok)
	assert.NotNil(t, vv.clientConfigLoader)
	assert.NotNil(t, vv.clientsetLoader)
}

func TestValidateKubeconfig(t *testing.T) {
	logger, _ := zap.NewDevelopment()

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
		name       string
		setupFunc  func(v *validator)
		assertions func(t *testing.T, v *validator)
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
			assertions: func(t *testing.T, v *validator) {
				err := v.Validate("path", false)
				assert.NoError(t, err)
			},
		},
		{
			name: "the REST config cannot be loaded from the specified kubeconfig",
			setupFunc: func(v *validator) {
				v.clientConfigLoader = func(kubeconfigPath string) (*restclient.Config, error) {
					return nil, fmt.Errorf("unable to load kubeconfig")
				}
			},
			assertions: func(t *testing.T, v *validator) {
				err := v.Validate("path", false)
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "failed to create REST client config from kubeconfig")
				assert.Contains(t, err.Error(), "unable to load kubeconfig")
			},
		},
		{
			name: "cert data is empty",
			setupFunc: func(v *validator) {
				v.clientConfigLoader = func(kubeconfigPath string) (*restclient.Config, error) {
					return &restclient.Config{}, nil
				}
			},
			assertions: func(t *testing.T, v *validator) {
				err := v.Validate("path", false)
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "failed to validate client config contents: unable to load TLS certificates from existing kubeconfig")
				assert.Contains(t, err.Error(), "does not contain any valid RSA or ECDSA certificates")
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
			assertions: func(t *testing.T, v *validator) {
				err := v.Validate("path", false)
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "private key does not match public key")
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
			assertions: func(t *testing.T, v *validator) {
				err := v.Validate("path", false)
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "some part of the existing kubeconfig certificate has expired")
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := &validator{
				logger: logger,
			}
			tt.setupFunc(v)
			tt.assertions(t, v)
		})
	}
}

func TestEnsureAuthorizedClient(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	var clientset *fake.Clientset

	validCertPEM, validKeyPEM, err := testutil.GenerateCertPEM(testutil.CertTemplate{
		CommonName:   "cn",
		Organization: "org",
		Expiration:   time.Now().Add(time.Hour),
	})
	assert.NoError(t, err)

	tests := []struct {
		name       string
		setupFunc  func(v *validator, clientset *fake.Clientset)
		assertions func(t *testing.T, v *validator)
	}{
		{
			name: "clientset cannot be loaded from client REST config",
			setupFunc: func(v *validator, clientset *fake.Clientset) {
				v.clientsetLoader = func(clientConfig *restclient.Config) (kubernetes.Interface, error) {
					return nil, fmt.Errorf("bad rest config")
				}
			},
			assertions: func(t *testing.T, v *validator) {
				err := v.Validate("path", true)
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "failed to create clientset from REST client config")
				assert.Contains(t, err.Error(), "bad rest config")
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
			assertions: func(t *testing.T, v *validator) {
				err := v.Validate("path", true)
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "cannot make authorized request to list server version")
				assert.Contains(t, err.Error(), "client certificate signed by unknown authority")
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
			assertions: func(t *testing.T, v *validator) {
				err := v.Validate("path", true)
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "encountered an unexpected error when attempting to request server version info")
				assert.Contains(t, err.Error(), "server unavailable")
			},
		},
		{
			name:      "kubeconfig contains valid cert and key and can make an authorized request to the server",
			setupFunc: func(v *validator, clientset *fake.Clientset) {},
			assertions: func(t *testing.T, v *validator) {
				err := v.Validate("path", true)
				assert.NoError(t, err)
			},
		},
	} //testing gpg
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := &validator{
				logger: logger,
			}

			clientset = fake.NewSimpleClientset()
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
			tt.assertions(t, v)
		})
	}
}
