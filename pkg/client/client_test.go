// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.
package client

import (
	"context"
	"crypto/x509"
	"os"
	"strings"

	"github.com/Azure/aks-tls-bootstrap-client/pkg/datamodel"
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

var _ = Describe("TLS Bootstrap client tests", func() {
	var (
		bootstrapClient TLSBootstrapClient
	)

	BeforeEach(func() {
		bootstrapClient = &tlsBootstrapClientImpl{
			logger: testLogger,
		}
		testExecInfoJSON = strings.ReplaceAll(testExecInfoJSON, "\n", "")
		testExecInfoJSON = strings.ReplaceAll(testExecInfoJSON, "\t", "")
		os.Setenv("KUBERNETES_EXEC_INFO", testExecInfoJSON)
	})

	AfterEach(func() {
		os.Setenv("KUBERNETES_EXEC_INFO", "")
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
})
