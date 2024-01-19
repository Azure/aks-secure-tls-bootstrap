package client

import (
	"os"

	mocks "github.com/Azure/aks-tls-bootstrap-client/pkg/client/mocks"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"go.uber.org/mock/gomock"
	restclient "k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

const (
	dummyCertPem = `-----BEGIN CERTIFICATE-----
MIIC7jCCAdagAwIBAgIBATANBgkqhkiG9w0BAQsFADAeMQ0wCwYDVQQKEwR0ZXN0
MQ0wCwYDVQQDEwR0ZXN0MCAXDTI0MDExOTAwNDYyMloYDzIyMjQwMTE5MDA0NjIy
WjAeMQ0wCwYDVQQKEwR0ZXN0MQ0wCwYDVQQDEwR0ZXN0MIIBIjANBgkqhkiG9w0B
AQEFAAOCAQ8AMIIBCgKCAQEAnevpBEsn6CWxT6DkD9RjJnqSAjducV+FAkWwxZAt
GpwKJ2zVaD9x7zkKCpMmJi6kGD+sLZxhBu3hYEsJPzM0dEQbRPrChqhJbkSMm+AC
JVIeb2Dhy30scMl3/JGcrEejK79iWfY77VYE5grTrS4RM7/VUGZEahlKKSHEWqLg
xoNFeg8u3Im1+QwtJ4zYUNSTEIlyUmO1E6bvYaX7IibqEe2MszR4fV9BdzwisvWz
Xg+5t61Dj0lXATgRGpkRul5gsglTjYNyWdJfY4enqlPPDiaF8WUggLnmzsBBUB3s
Py4TuAI+yWa1riJRUIS39a/yzbsYODfGztsuvsFaoDlHQwIDAQABozUwMzAOBgNV
HQ8BAf8EBAMCBaAwEwYDVR0lBAwwCgYIKwYBBQUHAwEwDAYDVR0TAQH/BAIwADAN
BgkqhkiG9w0BAQsFAAOCAQEAiCmY9+ZDupvejgEyIwQ0T5q014yEdx5yeIfAOpuO
phHGI9BG3jxGXsTRE2yAwE+8jdgnbBCM5Ro38J96pk+OmnYyWjgm8f76BnUG7hcL
deI2t4uPx3i8HB76a+aYJr5FhNLFjkVELpxjZd87LTWEH3GAUOXROiBH30OJH9A9
StST8iIcfS0CODYjxMg99IJaam8JqomSCgE8C4G9PJhgLiabVkvw91GxSuPMVZOd
UrmxAqLW0KZr4p8Un11V5qxBUG3W1Rpr+lg9ZgzBb8NFm/Te5PgsTs+XZGhwX1TP
IcLUdsNaYM20dfj3jO0+5K3qn/tCabm9y1k6vMJPwpC/eQ==
-----END CERTIFICATE-----`

	dummyKeyPem = `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAnevpBEsn6CWxT6DkD9RjJnqSAjducV+FAkWwxZAtGpwKJ2zV
aD9x7zkKCpMmJi6kGD+sLZxhBu3hYEsJPzM0dEQbRPrChqhJbkSMm+ACJVIeb2Dh
y30scMl3/JGcrEejK79iWfY77VYE5grTrS4RM7/VUGZEahlKKSHEWqLgxoNFeg8u
3Im1+QwtJ4zYUNSTEIlyUmO1E6bvYaX7IibqEe2MszR4fV9BdzwisvWzXg+5t61D
j0lXATgRGpkRul5gsglTjYNyWdJfY4enqlPPDiaF8WUggLnmzsBBUB3sPy4TuAI+
yWa1riJRUIS39a/yzbsYODfGztsuvsFaoDlHQwIDAQABAoIBAF9AUK7XSf265mS6
DXUCzL8DxRdzKblWPNqvAD1Zher73SAEg/+57NW2mLjiImt7TFyX4xkrrlZImtzC
xZQKJYRPJAeKHFSuIoRQ8mJ+Ta0HB/Z0AB0Fpg1tZ2K+zToYh3G2oPLUEzdG3/OE
6kIVfCizd01kMbWxBUsj49QrU9pHlqSZx6UNi8k+nGtpIjX9HARIZhCNqAeQyAwe
HMPD8Jc569iAbDtp1dq2YELXWDssL7t5gqRa56dutxKFCIJvt2xDx8e0KQBeq+j4
18ERVf8sf1DkuV9AdV5mQef1J8htexvjTUu36AFtYRwQuBWs8e9891WUqrag1Y8j
gg73RgECgYEAweBMdX8WjdzfufV3l8I1Q3bnDI7DNifmP37nJJJRRfz1qWvXcPmz
7dY4MgGdwOopJA3LfsyE3zCq7IEe+3LK6ZQV29QkheExXEGj9s3e1AHnpCEeqKOK
qDMtxgOLpuh6hUZbSf069Fq7jpqo1c3lluIc9UStD2z3x+ApqDsJpkMCgYEA0IY+
tDet1s73s/o9uzJ9LleN7ieLYSDxg5oKvZpn3A4c9Rrr7Fj1OBNOkPjlUsVRSb6f
sMn1gz45cMc5eSSimen/R7MThcYUpN3EazWnZDS9DKN3PTwObONRj8g439AmIYLK
y279PO3yxhg3B4BfXgkKPUe/BEXoRVDxg8n+SwECgYBwfb6fZjAl/ARsF7teeLcD
ABirtqIZ6Ci2quFe3O7/VvkLZqFI0fnOhD9y9HEeID/ixYZPekeWYNysAXeCmmaW
BPBx7rOKYtGLICMM7wLdrIVFPFpXqxym35sti50aKUX90obhdWchpQuygJZ6B8+x
Ll1zCngHvUg/1xcUn7zHlQKBgG2F9S1HCWGH94Zqaz4FeMZ8aimqT4TGftO2dum7
Tc3BA+ihKUVMPBAl4+A1Oo3M4bMwEkQS74btidH4cfF1Eopw4wpPvnNG5NTrPh1p
YvA42wrmWNyqzJDYnKA+c9DqTPzQ658KPqxf9mGhmlWwUWbcrKofIu8loKe3qgKk
d5IBAoGBALYKNPHZasv6D8z1HfubW3k/G3EzVXYrrNQ8mOnJjbGhuFh29/CGyodp
LNSzVepEqDGARwkhMjpYMyXqUYlF+FpLo6WGmFxbhdTwD7uIAVf0vIfAhPzlaxeG
9OT27Rx4qVWDEuy+wCdkYMfbnBbfreLCuPsHTkkl/kncbhpxGXIo
-----END RSA PRIVATE KEY-----`
)

var _ = Describe("TLS Bootstrap kubeconfig tests", func() {
	var (
		mockCtrl            *gomock.Controller
		imdsClient          *mocks.MockImdsClient
		aadClient           *mocks.MockAadClient
		tlsBootstrapClient  *tlsBootstrapClientImpl
		mockReader          *mocks.MockfileReader
		validKubeConfigPath string
	)

	Context("isKubeConfigStillValid Tests", func() {
		BeforeEach(func() {
			validKubeConfigPath = "dummykubeconfig"
			_, err := os.Create(validKubeConfigPath)

			if err != nil {
				return
			}

			bootstrapClientConfig := &restclient.Config{
				Host: "https://your-k8s-cluster.com",
				TLSClientConfig: restclient.TLSClientConfig{
					CertData: []byte(dummyCertPem),
					KeyData:  []byte(dummyKeyPem),
				},
				BearerToken: "your-token",
			}
			err = writeKubeconfigFromBootstrapping(bootstrapClientConfig, validKubeConfigPath)
			if err != nil {
				return
			}

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
			err := os.Remove(validKubeConfigPath)
			if err != nil {
				return
			}

			mockCtrl.Finish()
		})

		When("kubeconfig is valid", func() {
			It("should return true and nil error", func() {
				isValid, err := isKubeConfigStillValid(validKubeConfigPath, tlsBootstrapClient.logger)
				Expect(isValid).To(Equal(true))
				Expect(err).To(BeNil())

			})
		})

		When("kubeconfg is empty", func() {
			It("should return false and have error", func() {
				_, err := os.Create(validKubeConfigPath) // overwrite the kubeconfig file with an empty file
				Expect(err).To(BeNil())

				isValid, err := isKubeConfigStillValid(validKubeConfigPath, tlsBootstrapClient.logger)
				Expect(isValid).To(Equal(false))
				Expect(err).ToNot(BeNil())
				Expect(err.Error()).To(ContainSubstring("unable to load kubeconfig"))
			})
		})

	})
})

// taken and modified from
// https://github.com/kubernetes/kubernetes/blob/master/pkg/kubelet/certificate/bootstrap/bootstrap.go#L178-L210
func writeKubeconfigFromBootstrapping(bootstrapClientConfig *restclient.Config, kubeconfigPath string) error {
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

	// Marshal to disk
	return clientcmd.WriteToFile(kubeconfigData, kubeconfigPath)
}
