// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package kubeconfig

import (
	"fmt"
	"time"

	"github.com/Azure/aks-secure-tls-bootstrap/client/internal/testutil"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	fakediscovery "k8s.io/client-go/discovery/fake"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	restclient "k8s.io/client-go/rest"
	"k8s.io/client-go/testing"
)

var _ = Describe("Validator", func() {
	Context("NewValidator", func() {
		It("should construct and return a new validator", func() {
			v := NewValidator()
			Expect(v).ToNot(BeNil())

			vv, ok := v.(*validator)
			Expect(ok).To(BeTrue())
			Expect(vv.clientConfigLoader).ToNot(BeNil())
			Expect(vv.clientsetLoader).ToNot(BeNil())
		})
	})

	Context("Validate", func() {
		var v *validator

		validCertPEM, validKeyPEM, err := testutil.GenerateCertPEMWithExpiration(testutil.CertTemplate{
			CommonName:   "cn",
			Organization: "org",
			Expiration:   time.Now().Add(time.Hour),
		})
		Expect(err).To(BeNil())

		expiredCertPEM, expiredKeyPEM, err := testutil.GenerateCertPEMWithExpiration(testutil.CertTemplate{
			CommonName:   "cn",
			Organization: "org",
			Expiration:   time.Now().Add(-1 * time.Hour),
		})
		Expect(err).To(BeNil())

		otherValidKeyPEM, err := testutil.GeneratePrivateKeyPEM()
		Expect(err).To(BeNil())

		BeforeEach(func() {
			v = &validator{}
		})

		When("kubeconfig is valid", func() {
			It("should validate the kubeconfig without error", func() {
				v.clientConfigLoader = func(kubeconfigPath string) (*restclient.Config, error) {
					return &restclient.Config{
						Host: "https://controlplane.azmk8s.io",
						TLSClientConfig: restclient.TLSClientConfig{
							CertData: validCertPEM,
							KeyData:  validKeyPEM,
						},
					}, nil
				}

				err := v.Validate("path", false)
				Expect(err).To(BeNil())
			})
		})

		When("the REST config cannot be loaded from the specified kubeconfig", func() {
			It("should return an error", func() {
				v.clientConfigLoader = func(kubeconfigPath string) (*restclient.Config, error) {
					return nil, fmt.Errorf("unable to load kubeconfig")
				}

				err := v.Validate("path", false)
				Expect(err).ToNot(BeNil())
				Expect(err.Error()).To(ContainSubstring("failed to create REST client config from kubeconfig"))
				Expect(err.Error()).To(ContainSubstring("unable to load kubeconfig"))
			})
		})

		When("cert data is empty", func() {
			It("should return an error", func() {
				v.clientConfigLoader = func(kubeconfigPath string) (*restclient.Config, error) {
					return &restclient.Config{}, nil
				}

				err := v.Validate("path", false)
				Expect(err).ToNot(BeNil())
				Expect(err.Error()).To(ContainSubstring("failed to validate client config contents: unable to load TLS certificates from existing kubeconfig"))
				Expect(err.Error()).To(ContainSubstring("does not contain any valid RSA or ECDSA certificates"))
			})
		})

		When("specified private key is not compatible with specified certificate", func() {
			It("should return an error", func() {
				v.clientConfigLoader = func(kubeconfigPath string) (*restclient.Config, error) {
					return &restclient.Config{
						Host: "https://controlplane.azmk8s.io",
						TLSClientConfig: restclient.TLSClientConfig{
							CertData: validCertPEM,
							KeyData:  otherValidKeyPEM,
						},
					}, nil
				}

				err := v.Validate("path", false)
				Expect(err).ToNot(BeNil())
				Expect(err.Error()).To(ContainSubstring("private key does not match public key"))
			})
		})

		When("certificate has expired", func() {
			It("should return an error", func() {
				v.clientConfigLoader = func(kubeconfigPath string) (*restclient.Config, error) {
					return &restclient.Config{
						Host: "https://controlplane.azmk8s.io",
						TLSClientConfig: restclient.TLSClientConfig{
							CertData: expiredCertPEM,
							KeyData:  expiredKeyPEM,
						},
					}, nil
				}

				err := v.Validate("path", false)
				Expect(err).ToNot(BeNil())
				Expect(err.Error()).To(ContainSubstring("some part of the existing kubeconfig certificate has expired"))
			})
		})

		Context("ensureAuthorizedClient is true", func() {
			var (
				clientset *fake.Clientset
			)

			BeforeEach(func() {
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
			})

			When("clientset cannot be loaded from client REST config", func() {
				It("should return an error", func() {
					v.clientsetLoader = func(clientConfig *restclient.Config) (kubernetes.Interface, error) {
						return nil, fmt.Errorf("bad rest config")
					}
					err := v.Validate("path", true)
					Expect(err).ToNot(BeNil())
					Expect(err.Error()).To(ContainSubstring("failed to create clientset from REST client config"))
					Expect(err.Error()).To(ContainSubstring("bad rest config"))
				})
			})

			When("kubeconfig contains valid cert and key but is still unauthorized", func() {
				It("should return an error", func() {
					clientset.Discovery().(*fakediscovery.FakeDiscovery).
						PrependReactor("get", "version", func(action testing.Action) (handled bool, ret runtime.Object, err error) {
							return true, nil, errors.NewUnauthorized("client certificate signed by unknown authority")
						})

					err := v.Validate("path", true)
					Expect(err).ToNot(BeNil())
					Expect(err.Error()).To(ContainSubstring("cannot make authorized request to list server version"))
					Expect(err.Error()).To(ContainSubstring("client certificate signed by unknown authority"))
				})
			})

			When("kubeconfig contains valid cert and key but server list returns unknown error", func() {
				It("should return an error", func() {
					clientset.Discovery().(*fakediscovery.FakeDiscovery).
						PrependReactor("get", "version", func(action testing.Action) (handled bool, ret runtime.Object, err error) {
							return true, nil, errors.NewInternalError(fmt.Errorf("server unavailable"))
						})

					err := v.Validate("path", true)
					Expect(err).ToNot(BeNil())
					Expect(err.Error()).To(ContainSubstring("encountered an unexpected error when attempting to request server version info"))
					Expect(err.Error()).To(ContainSubstring("server unavailable"))
				})
			})

			When("kubeconfig contains valid cert and key and can make an authorized request to the server", func() {
				It("should validate without error", func() {
					err := v.Validate("path", true)
					Expect(err).To(BeNil())
				})
			})
		})
	})
})
