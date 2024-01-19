package client

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"strings"
	"time"

	mocks "github.com/Azure/aks-tls-bootstrap-client/pkg/client/mocks"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"go.uber.org/mock/gomock"
	restclient "k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

const tempKubeConfigName = "dummykubeconfig"
const tempKubeConfigLocation = "."

var _ = Describe("TLS Bootstrap kubeconfig tests", func() {
	var (
		mockCtrl           *gomock.Controller
		imdsClient         *mocks.MockImdsClient
		aadClient          *mocks.MockAadClient
		tlsBootstrapClient *tlsBootstrapClientImpl
		mockReader         *mocks.MockfileReader
	)

	Context("isKubeConfigStillValid Tests", func() {
		BeforeEach(func() {

			mockCtrl = gomock.NewController(GinkgoT())
			imdsClient = mocks.NewMockImdsClient(mockCtrl)
			aadClient = mocks.NewMockAadClient(mockCtrl)
			mockReader = mocks.NewMockfileReader(mockCtrl)

			tlsBootstrapClient = &tlsBootstrapClientImpl{
				logger:     testLogger,
				imdsClient: imdsClient,
				aadClient:  aadClient,
				reader:     mockReader,
			}
		})

		AfterEach(func() {
			mockCtrl.Finish()
		})

		When("kubeconfig is valid", func() {
			It("should return true and nil error", func() {
				tempFile, err := os.CreateTemp(tempKubeConfigLocation, tempKubeConfigName)
				Expect(err).To(BeNil())
				defer os.Remove(tempFile.Name())

				certPem, keyPem, err := generateMockCertPEMWithExpiration("test", "test", time.Now().AddDate(200, 0, 0))
				Expect(err).To(BeNil())

				bootstrapClientConfig := &restclient.Config{
					Host: "https://your-k8s-cluster.com",
					TLSClientConfig: restclient.TLSClientConfig{
						CertData: certPem,
						KeyData:  keyPem,
					},
				}
				err = writeKubeconfigFromBootstrapping(bootstrapClientConfig, tempFile.Name(), false)
				Expect(err).To(BeNil())

				isValid, err := isKubeConfigStillValid(tempFile.Name(), tlsBootstrapClient.logger)
				Expect(isValid).To(Equal(true))
				Expect(err).To(BeNil())
			})
		})

		When("kubeconfg is empty", func() {
			It("should return false and have error", func() {
				tempFile, err := os.CreateTemp(tempKubeConfigLocation, tempKubeConfigName)
				Expect(err).To(BeNil())
				defer os.Remove(tempFile.Name())

				isValid, err := isKubeConfigStillValid(tempFile.Name(), tlsBootstrapClient.logger)
				Expect(isValid).To(Equal(false))
				Expect(err).ToNot(BeNil())
				Expect(err.Error()).To(ContainSubstring("unable to load kubeconfig"))
			})
		})

		When("kubeconfig path is malformed", func() {
			It("should return false and not error", func() {
				longPath := strings.Repeat("a", 1<<16) // a string with 65536 characters
				isValid, err := isKubeConfigStillValid(longPath, tlsBootstrapClient.logger)
				Expect(isValid).To(Equal(false))
				Expect(err).To(BeNil())
			})
		})

		When("keyPem does not belong to certPem", func() {
			It("should return false and have error", func() {
				tempFile, err := os.CreateTemp(tempKubeConfigLocation, tempKubeConfigName)
				Expect(err).To(BeNil())
				defer os.Remove(tempFile.Name())

				certPem, _, err := generateMockCertPEMWithExpiration("test", "test", time.Now().AddDate(200, 0, 0))
				Expect(err).To(BeNil())
				_, differentKeyPem, err := generateMockCertPEMWithExpiration("test", "test", time.Now().AddDate(200, 0, 0))
				Expect(err).To(BeNil())

				bootstrapClientConfig := &restclient.Config{
					Host: "https://your-k8s-cluster.com",
					TLSClientConfig: restclient.TLSClientConfig{
						CertData: certPem,
						KeyData:  differentKeyPem,
					},
				}
				err = writeKubeconfigFromBootstrapping(bootstrapClientConfig, tempFile.Name(), false)
				Expect(err).To(BeNil())

				isValid, err := isKubeConfigStillValid(tempFile.Name(), tlsBootstrapClient.logger)
				Expect(isValid).To(Equal(false))
				Expect(err).ToNot(BeNil())
				Expect(err.Error()).To(ContainSubstring("private key does not match public key"))
			})
		})

		When("certPem is expired", func() {
			It("should return false and not have an error", func() {
				tempFile, err := os.CreateTemp(tempKubeConfigLocation, tempKubeConfigName)
				Expect(err).To(BeNil())
				defer os.Remove(tempFile.Name())

				certPem, keyPem, err := generateMockCertPEMWithExpiration("test", "test", time.Now().AddDate(0, 0, -1))
				Expect(err).To(BeNil())

				bootstrapClientConfig := &restclient.Config{
					Host: "https://your-k8s-cluster.com",
					TLSClientConfig: restclient.TLSClientConfig{
						CertData: certPem,
						KeyData:  keyPem,
					},
				}
				err = writeKubeconfigFromBootstrapping(bootstrapClientConfig, tempFile.Name(), false)
				Expect(err).To(BeNil())

				isValid, err := isKubeConfigStillValid(tempFile.Name(), tlsBootstrapClient.logger)
				Expect(isValid).To(Equal(false))
				Expect(err).To(BeNil())
			})
		})

		When("When kubeconfig contains incorrect Clusters information", func() {
			It("should return false and have an error", func() {
				tempFile, err := os.CreateTemp(tempKubeConfigLocation, tempKubeConfigName)
				Expect(err).To(BeNil())
				defer os.Remove(tempFile.Name())

				certPem, keyPem, err := generateMockCertPEMWithExpiration("test", "test", time.Now().AddDate(200, 0, 0))
				Expect(err).To(BeNil())

				bootstrapClientConfig := &restclient.Config{
					Host: "https://your-k8s-cluster.com",
					TLSClientConfig: restclient.TLSClientConfig{
						CertData: certPem,
						KeyData:  keyPem,
					},
				}
				bootstrapClientConfig.ExecProvider = &clientcmdapi.ExecConfig{Command: "dummy"}
				bootstrapClientConfig.AuthProvider = &clientcmdapi.AuthProviderConfig{Name: "dummy",
					Config: map[string]string{
						"key": "value",
					}}

				err = writeKubeconfigFromBootstrapping(bootstrapClientConfig, tempFile.Name(), true)
				Expect(err).To(BeNil())

				isValid, err := isKubeConfigStillValid(tempFile.Name(), tlsBootstrapClient.logger)
				Expect(isValid).To(Equal(false))
				Expect(err).ToNot(BeNil())
				Expect(err.Error()).To(ContainSubstring("exec plugin: invalid apiVersion"))
			})
		})

		When("kubeconfig does not exist", func() {
			It("should return false and not have an error", func() {
				isValid, err := isKubeConfigStillValid("dummy", tlsBootstrapClient.logger)
				Expect(isValid).To(Equal(false))
				Expect(err).To(BeNil())
			})
		})
	})
})

// taken and modified from
// https://github.com/kubernetes/kubernetes/blob/master/pkg/kubelet/certificate/bootstrap/bootstrap.go#L178-L210
func writeKubeconfigFromBootstrapping(bootstrapClientConfig *restclient.Config, kubeconfigPath string, brokenAuthInfo bool) error {
	// Get the CA data from the bootstrap client config.
	caFile, caData := bootstrapClientConfig.CAFile, []byte{}

	// Build resulting kubeconfig.
	kubeconfigData := clientcmdapi.Config{
		// Define a cluster stanza based on the bootstrap kubeconfig.
		Clusters: map[string]*clientcmdapi.Cluster{"default-cluster": {
			Server:                   bootstrapClientConfig.Host,
			InsecureSkipTLSVerify:    bootstrapClientConfig.Insecure,
			CertificateAuthority:     caFile,
			CertificateAuthorityData: caData,
		}},
		// Define auth based on the obtained client cert.
		AuthInfos: map[string]*clientcmdapi.AuthInfo{"default-auth": {
			ClientCertificateData: bootstrapClientConfig.TLSClientConfig.CertData,
			ClientKeyData:         bootstrapClientConfig.TLSClientConfig.KeyData,
		}},
		// Define a context that connects the auth info and cluster, and set it as the default
		Contexts: map[string]*clientcmdapi.Context{"default-context": {
			Cluster:   "default-cluster",
			AuthInfo:  "default-auth",
			Namespace: "default",
		}},
		CurrentContext: "default-context",
	}

	if brokenAuthInfo {
		kubeconfigData.AuthInfos = map[string]*clientcmdapi.AuthInfo{"default-auth": {
			ClientCertificateData: bootstrapClientConfig.TLSClientConfig.CertData,
			ClientKeyData:         bootstrapClientConfig.TLSClientConfig.KeyData,
			Exec: &clientcmdapi.ExecConfig{
				Command:         "dummy",
				APIVersion:      "dummyVersion",
				InteractiveMode: clientcmdapi.AlwaysExecInteractiveMode,
			},
		}}
	}

	// Marshal to disk
	return clientcmd.WriteToFile(kubeconfigData, kubeconfigPath)
}

func generateMockCertPEMWithExpiration(cn string, org string, expiration time.Time) ([]byte, []byte, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
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
	if err != nil {
		return nil, nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})

	return certPEM, keyPEM, nil
}
