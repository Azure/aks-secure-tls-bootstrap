// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.
package client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"os"
	"strings"

	"github.com/Azure/aks-tls-bootstrap-client/pkg/datamodel"
	pb "github.com/Azure/aks-tls-bootstrap-client/pkg/protos"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var (
	testExecInfoJSON = `{
"apiVersion": "client.authentication.k8s.io/v1",
"kind": "ExecCredential",
"spec": {
	"cluster": {
		"certificate-authority-data": "cadata",
		"config": {},
		"insecure-skip-tls-verify": false,
		"proxy-url": "proxyurl",
		"server": "https://1.2.3.4:6443",
		"tls-server-name": "someserver"
	},
	"interactive": false
},
"status": {
	"clientCertificateData": "certdata",
	"clientKeyData": "keydata",
	"token": "token"
}
}`
)

const exampleCACert = `-----BEGIN CERTIFICATE-----
MIIE6DCCAtCgAwIBAgIQOW6Z2RWWbs0WB/DvwlB+ATANBgkqhkiG9w0BAQsFADAN
MQswCQYDVQQDEwJjYTAgFw0yMzA1MTkxNzU5MjlaGA8yMDUzMDUxOTE4MDkyOVow
DTELMAkGA1UEAxMCY2EwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQC9
L7Gi07FkJ1YUMxhwobgJ+a0zLRIPF4HPRyJtXEbplTCxPGkROexSoIoFgg+YEuf7
mGxgpiDWch8modzOp5tPu+uLx/dpQmTapx1/4SeGBrPI6wpkWw47P6UNxU9kpBV2
qes0IQMp+BVVoPPVIGIzjbaHX74LwxdiPsOQlo5NZSUpoRBubEaCq/tDwyTn/q1c
rYIJz3i/0H50OIqp+Y5QsPhVaGIX+wcOUnmJZwhry0GWMUO6TJ5Q6adM+72daIft
447xkQJ63WItYfZBS8ndkdSDG39531030CFKDSPAfvkg90tBc73SyzXcpbBILslw
f1kuegMP7RUOcrbxFlTdPEEBK69bGSiWMbzfjMP5+u9mJw566x5p0rR9bPlUfudy
7lDp8n5g75HMCPKurdB9at9oAMqAhUZwQgNhbmbflQ2yJ8ajpjreNWSQ+3gBUfwC
5mFdurpktlClcAWxLmr9sgld2mb+S1RU4HdEkNlT+Ag5TAG/8Q9ZeRCDyhvBpRI/
fIV1Ezwy0JIpxQPUoZacRiuvRyLQEWGNup/aAg8RNk8KGZU2MaidVSZVM5j8TWlp
DK3KzU3IBqfjFD4Kc8IMQbd62SRn9slOvH6FJb+7+tMOrmrL8zNAUxeWFOdQR5KJ
LO11D6pv4g4kdQeHgWhG/DEZJuWM6pmfrxpbbvSXKwIDAQABo0IwQDAOBgNVHQ8B
Af8EBAMCAqQwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUS9ouas22EITY6YCF
AfLqFI0oFUUwDQYJKoZIhvcNAQELBQADggIBAC8LAQ+ge40bFtl4gEeLpDAY5erK
+CHvHitqxR4i807lVK45aHug7hBLJDOnyukri3+aJqpIWiZv4WEU++4Yfl2qu9pz
koPk8W8/A+YPMjPkVePUz47BC6CODx0W6CK4YtbDS8Ar0Rn140RTUlnfX54S4W5o
OUc2jnGFjeFaPB17jDohm8b3y0B1jycVtt0QfAxqT7gNhj19GF/20VfuUPBtRAf7
Y42cKEeQ6/VsnJR0+nVpJsGo8WBsAdL/uLLvpN70NWIIS7qYjuCQElt/1rq+HNXg
Rxe4xcS0NqHm/DyUwalmrPKX/WlX44KM7veQ4hVH2YRBgTCnpKN/ccY6KHwWb+hF
F/xNORPQqL/9K9GMUjP93oJuiqwXvC+pJLn/SaApuNbYQ67vrA2vPzmADC1RGcVE
z3qV9ZnEqFRDwP1dk5++NSUnq4KBN+X9guR3fQTujW31TM6j49Svh7R1LezrmuEp
MQHO4RsZXjy/Fi4SzOyQyTPsrF5HXo+x6Z1WoXzXTZz6w4sWeioIYogpv0flePu4
01RuufRhuVupDKObKe5F3JkMSf3lFV79Tt2x/txc9CwoyxPZUWQIdSlbl1Grp+on
wEqb8vx9lRpm8Tuo3Pw3MZ8upt8aHTn/BB61YkDsNdAZAWGKgv77doGsWwqWtb+m
h/ZvW8MtN313Ykv4
-----END CERTIFICATE-----`

func mockSetupClientConnectionFuncs(mockExecCredential *datamodel.ExecCredential) {
	newLoadExecCredential = func() (*datamodel.ExecCredential, error) {
		return mockExecCredential, nil
	}
	newGetTlsConfig = func(pemCAs []byte, c *tlsBootstrapClientImpl, execCredential *datamodel.ExecCredential) (*tls.Config, error) {
		return &tls.Config{}, nil
	}
	newLoadAzureJson = func() (*datamodel.AzureConfig, error) {
		return &datamodel.AzureConfig{}, nil
	}
	newGetAuthToken = func(ctx context.Context, c *tlsBootstrapClientImpl, customClientID, resource string, azureConfig *datamodel.AzureConfig) (string, error) {
		return "", nil
	}
}

var _ = Describe("TLS Bootstrap client tests", func() {
	var (
		bootstrapClient    TLSBootstrapClient
		mockExecCredential *datamodel.ExecCredential

		// setupClientConnection mocks
		oldnewLoadExecCredential func() (*datamodel.ExecCredential, error)
		oldGetTlsConfig          func(pemCAs []byte, c *tlsBootstrapClientImpl, execCredential *datamodel.ExecCredential) (*tls.Config, error)
		oldLoadAzureJson         func() (*datamodel.AzureConfig, error)
		oldGetAuthToken          func(ctx context.Context, c *tlsBootstrapClientImpl, customClientID, resource string, azureConfig *datamodel.AzureConfig) (string, error)

		// GetBootstrapToken mocks
		oldGetInstanceData            func(ctx context.Context, c *tlsBootstrapClientImpl, imdsURL string) (*datamodel.VMSSInstanceData, error)
		oldPbClientGetNonce           func(ctx context.Context, pbClient pb.AKSBootstrapTokenRequestClient, nonceRequest *pb.NonceRequest) (*pb.NonceResponse, error)
		oldGetAttestedData            func(ctx context.Context, c *tlsBootstrapClientImpl, nonce string) (*datamodel.VMSSAttestedData, error)
		oldPbClientGetToken           func(ctx context.Context, pbClient pb.AKSBootstrapTokenRequestClient, tokenRequest *pb.TokenRequest) (*pb.TokenResponse, error)
		oldGetExecCredentialWithToken func(token string, expirationTimestamp string) (*datamodel.ExecCredential, error)
	)

	BeforeEach(func() {
		bootstrapClient = &tlsBootstrapClientImpl{
			logger: testLogger,
		}
		testExecInfoJSON = strings.ReplaceAll(testExecInfoJSON, "\n", "")
		testExecInfoJSON = strings.ReplaceAll(testExecInfoJSON, "\t", "")
		os.Setenv("KUBERNETES_EXEC_INFO", testExecInfoJSON)

		mockExecCredential = &datamodel.ExecCredential{Spec: struct {
			Cluster struct {
				CertificateAuthorityData string      "json:\"certificate-authority-data,omitempty\""
				Config                   interface{} "json:\"config,omitempty\""
				InsecureSkipTLSVerify    bool        "json:\"insecure-skip-tls-verify,omitempty\""
				ProxyURL                 string      "json:\"proxy-url,omitempty\""
				Server                   string      "json:\"server,omitempty\""
				TLSServerName            string      "json:\"tls-server-name,omitempty\""
			} "json:\"cluster,omitempty\""
			Interactive bool "json:\"interactive,omitempty\""
		}{}}

		// save all function implementations so that they can be resotred on cleanup
		oldnewLoadExecCredential = newLoadExecCredential
		oldGetTlsConfig = newGetTlsConfig
		oldLoadAzureJson = newLoadAzureJson
		oldGetAuthToken = newGetAuthToken

		oldGetInstanceData = newGetInstanceData
		oldPbClientGetNonce = newPbClientGetNonce
		oldGetAttestedData = newGetAttestedData
		oldPbClientGetToken = newPbClientGetToken
		oldGetExecCredentialWithToken = newGetExecCredentialWithToken
	})

	AfterEach(func() {
		os.Setenv("KUBERNETES_EXEC_INFO", "")

		// restore all mocked functions
		newLoadExecCredential = oldnewLoadExecCredential
		newGetTlsConfig = oldGetTlsConfig
		newLoadAzureJson = oldLoadAzureJson
		newGetAuthToken = oldGetAuthToken

		newGetInstanceData = oldGetInstanceData
		newPbClientGetNonce = oldPbClientGetNonce
		newGetAttestedData = oldGetAttestedData
		newPbClientGetToken = oldPbClientGetToken
		newGetExecCredentialWithToken = oldGetExecCredentialWithToken
	})

	Context("Test GetBootstrapToken", func() {
		It("should return an error when KUBERNETES_EXEC_INFO is missing", func() {
			os.Setenv("KUBERNETES_EXEC_INFO", "")
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			token, err := bootstrapClient.GetBootstrapToken(ctx)
			Expect(token).To(BeEmpty())
			Expect(err).ToNot(BeNil())
			Expect(err.Error()).To(ContainSubstring("KUBERNETES_EXEC_INFO must be set to retrieve bootstrap token"))
		})

		When("setupClientConnection and getInstanceData are mocked to succeed", func() {
			It("should fail to recieve nonce", func() {
				os.Setenv("KUBERNETES_EXEC_INFO", "")
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()

				mockSetupClientConnectionFuncs(mockExecCredential)
				newGetInstanceData = func(ctx context.Context, c *tlsBootstrapClientImpl, imdsURL string) (*datamodel.VMSSInstanceData, error) {
					return &datamodel.VMSSInstanceData{}, nil
				}

				token, err := bootstrapClient.GetBootstrapToken(ctx)
				Expect(token).To(BeEmpty())
				Expect(err).ToNot(BeNil())
				Expect(err.Error()).To(ContainSubstring("failed to retrieve a nonce"))
			})
		})

		When("setupClientConnection is mocked to succeed but getInstanceData is not mocked", func() {
			It("should panic on getInstanceData", func() {
				os.Setenv("KUBERNETES_EXEC_INFO", "")
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()

				mockSetupClientConnectionFuncs(mockExecCredential)

				Expect(func() {
					bootstrapClient.GetBootstrapToken(ctx)
				}).To(Panic())
			})
		})

		When("GetNonce and GetAttestedData are mocked to succeed", func() {
			It("should fail to get a token", func() {
				os.Setenv("KUBERNETES_EXEC_INFO", "")
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()

				mockSetupClientConnectionFuncs(mockExecCredential)
				newGetInstanceData = func(ctx context.Context, c *tlsBootstrapClientImpl, imdsURL string) (*datamodel.VMSSInstanceData, error) {
					return &datamodel.VMSSInstanceData{}, nil
				}
				newPbClientGetNonce = func(ctx context.Context, pbClient pb.AKSBootstrapTokenRequestClient, nonceRequest *pb.NonceRequest) (*pb.NonceResponse, error) {
					return &pb.NonceResponse{}, nil
				}
				newGetAttestedData = func(ctx context.Context, c *tlsBootstrapClientImpl, nonce string) (*datamodel.VMSSAttestedData, error) {
					return &datamodel.VMSSAttestedData{}, nil
				}

				token, err := bootstrapClient.GetBootstrapToken(ctx)
				Expect(token).To(BeEmpty())
				Expect(err).ToNot(BeNil())
				Expect(err.Error()).To(ContainSubstring("failed to retrieve a token"))
			})
		})

		When("GetNonce is mocked but GetAttestedData is not mocked", func() {
			It("should fail to get a token", func() {
				os.Setenv("KUBERNETES_EXEC_INFO", "")
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()

				mockSetupClientConnectionFuncs(mockExecCredential)
				newGetInstanceData = func(ctx context.Context, c *tlsBootstrapClientImpl, imdsURL string) (*datamodel.VMSSInstanceData, error) {
					return &datamodel.VMSSInstanceData{}, nil
				}
				newPbClientGetNonce = func(ctx context.Context, pbClient pb.AKSBootstrapTokenRequestClient, nonceRequest *pb.NonceRequest) (*pb.NonceResponse, error) {
					return &pb.NonceResponse{}, nil
				}

				Expect(func() {
					bootstrapClient.GetBootstrapToken(ctx)
				}).To(Panic())
			})
		})

		When("PbClientGetToken is mocked to succeed", func() {
			It("should fail to generate new exec credential", func() {
				os.Setenv("KUBERNETES_EXEC_INFO", "")
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()

				mockSetupClientConnectionFuncs(mockExecCredential)
				newGetInstanceData = func(ctx context.Context, c *tlsBootstrapClientImpl, imdsURL string) (*datamodel.VMSSInstanceData, error) {
					return &datamodel.VMSSInstanceData{}, nil
				}
				newPbClientGetNonce = func(ctx context.Context, pbClient pb.AKSBootstrapTokenRequestClient, nonceRequest *pb.NonceRequest) (*pb.NonceResponse, error) {
					return &pb.NonceResponse{}, nil
				}
				newGetAttestedData = func(ctx context.Context, c *tlsBootstrapClientImpl, nonce string) (*datamodel.VMSSAttestedData, error) {
					return &datamodel.VMSSAttestedData{}, nil
				}
				newPbClientGetToken = func(ctx context.Context, pbClient pb.AKSBootstrapTokenRequestClient, tokenRequest *pb.TokenRequest) (*pb.TokenResponse, error) {
					return &pb.TokenResponse{}, nil
				}

				token, err := bootstrapClient.GetBootstrapToken(ctx)
				Expect(token).To(BeEmpty())
				Expect(err).ToNot(BeNil())
				Expect(err.Error()).To(ContainSubstring("generate new exec credential"))
			})
		})

		When("getExecCredentialWithToken is mocked to succeed", func() {
			It("should return a bootstrap token", func() {
				os.Setenv("KUBERNETES_EXEC_INFO", "")
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()

				mockSetupClientConnectionFuncs(mockExecCredential)
				newGetInstanceData = func(ctx context.Context, c *tlsBootstrapClientImpl, imdsURL string) (*datamodel.VMSSInstanceData, error) {
					return &datamodel.VMSSInstanceData{}, nil
				}
				newPbClientGetNonce = func(ctx context.Context, pbClient pb.AKSBootstrapTokenRequestClient, nonceRequest *pb.NonceRequest) (*pb.NonceResponse, error) {
					return &pb.NonceResponse{}, nil
				}
				newGetAttestedData = func(ctx context.Context, c *tlsBootstrapClientImpl, nonce string) (*datamodel.VMSSAttestedData, error) {
					return &datamodel.VMSSAttestedData{}, nil
				}
				newPbClientGetToken = func(ctx context.Context, pbClient pb.AKSBootstrapTokenRequestClient, tokenRequest *pb.TokenRequest) (*pb.TokenResponse, error) {
					return &pb.TokenResponse{}, nil
				}
				newGetExecCredentialWithToken = func(token string, expirationTimestamp string) (*datamodel.ExecCredential, error) {
					return &datamodel.ExecCredential{}, nil
				}

				token, err := bootstrapClient.GetBootstrapToken(ctx)
				Expect(token).ToNot(BeEmpty())
				Expect(err).To(BeNil())
			})
		})
	})

	Context("Test loadExecCredential", func() {
		When("ExecCredential JSON is properly formed", func() {
			It("should correctly parse and load the exec credential", func() {
				execCredential, err := loadExecCredential()
				Expect(err).To(BeNil())
				Expect(execCredential).ToNot(BeNil())
				Expect(execCredential.APIVersion).To(Equal("client.authentication.k8s.io/v1"))
				Expect(execCredential.Kind).To(Equal("ExecCredential"))
				Expect(execCredential.Spec.Cluster.CertificateAuthorityData).To(Equal("cadata"))
				Expect(execCredential.Spec.Cluster.InsecureSkipTLSVerify).To(BeFalse())
				Expect(execCredential.Spec.Cluster.ProxyURL).To(Equal("proxyurl"))
				Expect(execCredential.Spec.Cluster.Server).To(Equal("https://1.2.3.4:6443"))
				Expect(execCredential.Spec.Cluster.TLSServerName).To(Equal("someserver"))
				Expect(execCredential.Spec.Interactive).To(BeFalse())
				Expect(execCredential.Status.ClientCertificateData).To(Equal("certdata"))
				Expect(execCredential.Status.ClientKeyData).To(Equal("keydata"))
				Expect(execCredential.Status.Token).To(Equal("token"))
			})
		})

		When("ExecCredential JSON is malformed", func() {
			execCredential, err := loadExecCredential()
			Expect(err).ToNot(BeNil())
			Expect(execCredential).To(BeNil())
		})
	})

	Context("Test getServerURL", func() {
		It("should correctly join server name and port with a ':'", func() {
			execCredential := &datamodel.ExecCredential{}
			execCredential.Spec.Cluster.Server = "https://1.2.3.4:6443"
			serverURL, err := getServerURL(execCredential)
			Expect(err).To(BeNil())
			Expect(serverURL).To(Equal("1.2.3.4:6443"))
		})
	})

	Context("Test getTLSConfig", func() {
		var pemCAs = []byte(exampleCACert)

		When("nextProto is not supplied", func() {
			It("should not include NextProtos in returned config", func() {
				config, err := getTLSConfig(pemCAs, "", false)
				Expect(err).To(BeNil())
				Expect(config).ToNot(BeNil())
				Expect(config.NextProtos).To(BeNil())
				Expect(config.InsecureSkipVerify).To(BeFalse())

				pool := x509.NewCertPool()
				Expect(pool.AppendCertsFromPEM([]byte(exampleCACert))).To(BeTrue())
				Expect(config.RootCAs.Equal(pool)).To(BeTrue())
			})
		})

		When("nextProto is supplied", func() {
			It("should include NextProtos in returned config", func() {
				config, err := getTLSConfig(pemCAs, "nextProto", false)
				Expect(err).To(BeNil())
				Expect(config).NotTo(BeNil())
				Expect(config.NextProtos).NotTo(BeNil())
				Expect(config.NextProtos).To(Equal([]string{"nextProto", "h2"}))
				Expect(config.InsecureSkipVerify).To(BeFalse())

				pool := x509.NewCertPool()
				Expect(pool.AppendCertsFromPEM([]byte(exampleCACert))).To(BeTrue())
				Expect(config.RootCAs.Equal(pool)).To(BeTrue())
			})
		})

		When("insecureSkipVerify is false", func() {
			It("should return config with false value of InsecureSkipVerify", func() {
				config, err := getTLSConfig(pemCAs, "nextProto", false)
				Expect(err).To(BeNil())
				Expect(config).NotTo(BeNil())
				Expect(config.InsecureSkipVerify).To(BeFalse())

				pool := x509.NewCertPool()
				Expect(pool.AppendCertsFromPEM([]byte(exampleCACert))).To(BeTrue())
				Expect(config.RootCAs.Equal(pool)).To(BeTrue())
			})
		})

		When("insecureSkipVerify is true", func() {
			It("should return config with true value of InsecureSkipVerify", func() {
				config, err := getTLSConfig(pemCAs, "nextProto", true)
				Expect(err).To(BeNil())
				Expect(config).NotTo(BeNil())
				Expect(config.InsecureSkipVerify).To(BeTrue())

				pool := x509.NewCertPool()
				Expect(pool.AppendCertsFromPEM([]byte(exampleCACert))).To(BeTrue())
				Expect(config.RootCAs.Equal(pool)).To(BeTrue())
			})
		})
	})

	Context("Test setupClientConnection", func() {
		When("loadExecCredential is mocked to fail", func() {
			It("should fail on DecodeString", func() {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()

				mockExecCredential.Spec.Cluster.CertificateAuthorityData = "incorrectbase64"
				newLoadExecCredential = func() (*datamodel.ExecCredential, error) {
					return mockExecCredential, nil
				}

				conn, err := bootstrapClient.setupClientConnection(ctx)
				Expect(conn).To(BeNil())
				Expect(err).ToNot(BeNil())
				Expect(err.Error()).To(ContainSubstring("failed to decode"))
			})
		})

		When("loadExecCredential is mocked to succeed", func() {
			It("should fail on getTLSConfig", func() {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()

				newLoadExecCredential = func() (*datamodel.ExecCredential, error) {
					return mockExecCredential, nil
				}
				conn, err := bootstrapClient.setupClientConnection(ctx)
				Expect(conn).To(BeNil())
				Expect(err).ToNot(BeNil())
				Expect(err.Error()).To(ContainSubstring("failed to get TLS config"))
			})
		})

		When("getTlsConfig is mocked to succeed", func() {
			It("should fail on loadAzureJson", func() {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()

				newLoadExecCredential = func() (*datamodel.ExecCredential, error) {
					return mockExecCredential, nil
				}
				newGetTlsConfig = func(pemCAs []byte, c *tlsBootstrapClientImpl, execCredential *datamodel.ExecCredential) (*tls.Config, error) {
					return &tls.Config{}, nil
				}
				conn, err := bootstrapClient.setupClientConnection(ctx)
				Expect(conn).To(BeNil())
				Expect(err).ToNot(BeNil())
				Expect(err.Error()).To(ContainSubstring("failed to parse azure"))
			})
		})

		When("loadAzureJSON is mocked to succeed", func() {
			It("should fail on getAuthToken", func() {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()

				newLoadExecCredential = func() (*datamodel.ExecCredential, error) {
					return mockExecCredential, nil
				}
				newGetTlsConfig = func(pemCAs []byte, c *tlsBootstrapClientImpl, execCredential *datamodel.ExecCredential) (*tls.Config, error) {
					return &tls.Config{}, nil
				}
				newLoadAzureJson = func() (*datamodel.AzureConfig, error) {
					return &datamodel.AzureConfig{}, nil
				}
				conn, err := bootstrapClient.setupClientConnection(ctx)
				Expect(conn).To(BeNil())
				Expect(err).ToNot(BeNil())
			})
		})

		When("getAuthToken is mocked to succeed", func() {
			It("setupClientConnection should succeed", func() {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()

				newLoadExecCredential = func() (*datamodel.ExecCredential, error) {
					return mockExecCredential, nil
				}
				newGetTlsConfig = func(pemCAs []byte, c *tlsBootstrapClientImpl, execCredential *datamodel.ExecCredential) (*tls.Config, error) {
					return &tls.Config{}, nil
				}
				newLoadAzureJson = func() (*datamodel.AzureConfig, error) {
					return &datamodel.AzureConfig{}, nil
				}
				newGetAuthToken = func(ctx context.Context, c *tlsBootstrapClientImpl, customClientID, resource string, azureConfig *datamodel.AzureConfig) (string, error) {
					return "", nil
				}
				conn, err := bootstrapClient.setupClientConnection(ctx)
				Expect(conn).ToNot(BeNil())
				Expect(err).To(BeNil())
			})
		})
	})

	Context("Test getExecCredentialWithToken", func() {
		It("Shiuld return a new exec credential", func() {
			cred, err := getExecCredentialWithToken("dummyToken", "dummyTimestamp")
			Expect(err).To(BeNil())
			Expect(cred.Status.Token).To(Equal("dummyToken"))
			Expect(cred.Status.ExpirationTimestamp).To(Equal("dummyTimestamp"))
		})
	})
})
