// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package kubeconfig

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"

	"github.com/Azure/aks-secure-tls-bootstrap/client/pkg/testutil"
	. "github.com/onsi/ginkgo"
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
			validator := NewValidator()
			Expect(validator).ToNot(BeNil())
			Expect(validator.clientConfigLoader).ToNot(BeNil())
			Expect(validator.clientsetLoader).ToNot(BeNil())
		})
	})

	Context("Validate", func() {
		var validator *ValidatorImpl

		validCertPEM, validKeyPEM, err := testutil.GenerateCertPEMWithExpiration("cn", "org", time.Now().Add(time.Hour))
		Expect(err).To(BeNil())
		expiredCertPEM, expiredKeyPEM, err := testutil.GenerateCertPEMWithExpiration("cn", "org", time.Now().Add(-1*time.Hour))
		Expect(err).To(BeNil())
		otherValidKeyPEM, err := testutil.GeneratePrivateKeyPEM()
		Expect(err).To(BeNil())

		BeforeEach(func() {
			validator = NewValidator()
		})

		When("kubeconfig is valid", func() {
			It("should validate the kubeconfig without error", func() {
				validator.clientConfigLoader = func(kubeconfigPath string) (*restclient.Config, error) {
					return &restclient.Config{
						Host: "https://controlplane.azmk8s.io",
						TLSClientConfig: restclient.TLSClientConfig{
							CertData: validCertPEM,
							KeyData:  validKeyPEM,
						},
					}, nil
				}

				err := validator.Validate("path", false)
				Expect(err).To(BeNil())
			})
		})

		When("the REST config cannot be loaded from the specified kubeconfig", func() {
			It("should return an error", func() {
				validator.clientConfigLoader = func(kubeconfigPath string) (*restclient.Config, error) {
					return nil, fmt.Errorf("unable to load kubeconfig")
				}

				err := validator.Validate("path", false)
				Expect(err).ToNot(BeNil())
				Expect(err.Error()).To(ContainSubstring("failed to create REST client config from kubeconfig"))
				Expect(err.Error()).To(ContainSubstring("unable to load kubeconfig"))
			})
		})

		When("cert data is empty", func() {
			It("should return an error", func() {
				validator.clientConfigLoader = func(kubeconfigPath string) (*restclient.Config, error) {
					return &restclient.Config{}, nil
				}

				err := validator.Validate("path", false)
				Expect(err).ToNot(BeNil())
				Expect(err.Error()).To(ContainSubstring("failed to ensure client config contents: unable to load TLS certificates from existing kubeconfig"))
				Expect(err.Error()).To(ContainSubstring("does not contain any valid RSA or ECDSA certificates"))
			})
		})

		When("specified private key is not compatible with specified certificate", func() {
			It("should return an error", func() {
				validator.clientConfigLoader = func(kubeconfigPath string) (*restclient.Config, error) {
					return &restclient.Config{
						Host: "https://controlplane.azmk8s.io",
						TLSClientConfig: restclient.TLSClientConfig{
							CertData: validCertPEM,
							KeyData:  otherValidKeyPEM,
						},
					}, nil
				}

				err := validator.Validate("path", false)
				Expect(err).ToNot(BeNil())
				Expect(err.Error()).To(ContainSubstring("private key does not match public key"))
			})
		})

		When("certificate has expired", func() {
			It("should return an error", func() {
				validator.clientConfigLoader = func(kubeconfigPath string) (*restclient.Config, error) {
					return &restclient.Config{
						Host: "https://controlplane.azmk8s.io",
						TLSClientConfig: restclient.TLSClientConfig{
							CertData: expiredCertPEM,
							KeyData:  expiredKeyPEM,
						},
					}, nil
				}

				err := validator.Validate("path", false)
				Expect(err).ToNot(BeNil())
				Expect(err.Error()).To(ContainSubstring("some part of the existing kubeconfig certificate has expired"))
			})
		})

		Context("ensureAuthorization is true", func() {
			var (
				clientset *fake.Clientset
			)

			BeforeEach(func() {
				clientset = fake.NewSimpleClientset()
				validator.clientConfigLoader = func(kubeconfigPath string) (*restclient.Config, error) {
					return &restclient.Config{
						Host: "https://controlplane.azmk8s.io",
						TLSClientConfig: restclient.TLSClientConfig{
							CertData: validCertPEM,
							KeyData:  validKeyPEM,
						},
					}, nil
				}
				validator.clientsetLoader = func(clientConfig *restclient.Config) (kubernetes.Interface, error) {
					return clientset, nil
				}
			})

			When("clientset cannot be loaded from client REST config", func() {
				It("should return an error", func() {
					validator.clientsetLoader = func(clientConfig *restclient.Config) (kubernetes.Interface, error) {
						return nil, fmt.Errorf("bad rest config")
					}
					err := validator.Validate("path", true)
					Expect(err).ToNot(BeNil())
					Expect(err.Error()).To(ContainSubstring("failed to create clientset from client REST config"))
					Expect(err.Error()).To(ContainSubstring("bad rest config"))
				})
			})

			When("kubeconfig contains valid cert and key but is still unauthorized", func() {
				It("should return an error", func() {
					clientset.Discovery().(*fakediscovery.FakeDiscovery).
						PrependReactor("get", "version", func(action testing.Action) (handled bool, ret runtime.Object, err error) {
							return true, nil, errors.NewUnauthorized("client certificate signed by unknown authority")
						})

					err := validator.Validate("path", true)
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

					err := validator.Validate("path", true)
					Expect(err).ToNot(BeNil())
					Expect(err.Error()).To(ContainSubstring("encountered an unexpected error when attempting to request server version info"))
					Expect(err.Error()).To(ContainSubstring("server unavailable"))
				})
			})

			When("kubeconfig contains valid cert and key and can make an authorized request to the server", func() {
				It("should validate without error", func() {
					err := validator.Validate("path", true)
					Expect(err).To(BeNil())
				})
			})
		})
	})
})

func generateMockCertPEMWithExpiration(cn string, org string, expiration time.Time) ([]byte, []byte) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	Expect(err).To(BeNil())

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   cn,
			Organization: []string{org},
		},
		NotBefore: time.Now(),
		NotAfter:  expiration,

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	Expect(err).To(BeNil())

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})

	return certPEM, keyPEM
}

func generatePrivateKeyPEM() []byte {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	Expect(err).To(BeNil())
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})
	return keyPEM
}
