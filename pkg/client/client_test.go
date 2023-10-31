// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.
package client

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/Azure/aks-tls-bootstrap-client/pkg/client/mocks"
	"github.com/Azure/aks-tls-bootstrap-client/pkg/datamodel"
	pb "github.com/Azure/aks-tls-bootstrap-client/pkg/protos"
	protos_mock "github.com/Azure/aks-tls-bootstrap-client/pkg/protos/mocks"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"go.uber.org/mock/gomock"
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

var defaultPem = "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUZtakNDQTRJQ0NRQ0d3OEVzRExCNEl6QU5CZ2txaGtpRzl3MEJBUXNGQURDQmpqRUxNQWtHQTFVRUJoTUMKVlZNeEV6QVJCZ05WQkFnTUNsZGhjMmhwYm1kMGIyNHhFREFPQmdOVkJBY01CMU5sWVhSMGJHVXhFakFRQmdOVgpCQW9NQ1UxcFkzSnZjMjltZERFUk1BOEdBMVVFQ3d3SVRtOWtaU0JUYVdjeERUQUxCZ05WQkFNTUJHaHZjM1F4CklqQWdCZ2txaGtpRzl3MEJDUUVXRTJSMWJXMTVRRzFwWTNKdmMyOW1kQzVqYjIwd0hoY05Nak14TURJMk1qQXkKTkRJeVdoY05NalF4TURJMU1qQXlOREl5V2pDQmpqRUxNQWtHQTFVRUJoTUNWVk14RXpBUkJnTlZCQWdNQ2xkaApjMmhwYm1kMGIyNHhFREFPQmdOVkJBY01CMU5sWVhSMGJHVXhFakFRQmdOVkJBb01DVTFwWTNKdmMyOW1kREVSCk1BOEdBMVVFQ3d3SVRtOWtaU0JUYVdjeERUQUxCZ05WQkFNTUJHaHZjM1F4SWpBZ0Jna3Foa2lHOXcwQkNRRVcKRTJSMWJXMTVRRzFwWTNKdmMyOW1kQzVqYjIwd2dnSWlNQTBHQ1NxR1NJYjNEUUVCQVFVQUE0SUNEd0F3Z2dJSwpBb0lDQVFEWHp3Mytsb3NDY0IwbXJaSmg2aDZkaDVUYVdhK09hOHNpQTJsaUtFdDl6MXo0b2RYZVkxR3VTeTZkCnNienZ0RW1EVkR1QnBZM2lkaXQ0YVE4VHEzK2hMNnRTUUFXMkt5OG5ZU0YrMnMxRHBJcFg4TlJHbStyQ2hUNXEKOWpCY2pGUUIxdDdWTWZZd3hNL1RWQ3VuL0EvWjRIOUI1Sm9zc3BHdURMYjNEMzhUNDZRMmRsa3h6ODNMUVpONApscWM3cGJ4QlBRQk50TlF0WnhNNFZpRU1hdTV0Z293TlBIOG1MSHExMHpQS3pGMWE4b1R5Tnp4KzAyY0s3WVR1CjVFWTFwRDhLQnhlLzRrRjFKOGdsWFJmUFpEaTRmcG1QSUlCRFRSTmcvUmtmTFhRelRZL2RtOHZwcUZSaGgwdHQKZEZEdVRYRkFIWkJFTkZYMFdVS3ZhNXNLbVhuUW9ieS9GRGp1UGJtUmNvVjlEMC9hQnJVVG05bS8rZ05aa3BzMQplNTJreVBjSnJ2ZkhMdjdCTDI0cy9RQjhKMmlKYms2MHh4eUYzcUx1K2k4OE52anNScHVMb3QrTVYxNGFnc1VXCndhaXEvbHdXMjg1TGE4MUttak9WcEs0WHZ3VFJSRG5JZkZUcW9pMTJ2TllCaVphMVNnQUxUeWNVd1J0YU1NTE8KOE56U25FdHNIWWdBVnVKdTE3dUJiMDIyeGl5SU9VR0xSU2dUZnJoSHFjVklsQ0FkdzhwMnhRdjI2dDdVdTNBYwppRHlhQ2s2V1hyTTFhVGNSUzFWYS85ZnlWWmtJZEtNVGFpNHVJOEJzbXZtOGUwakJtRGF1Zyt5VWxDdmVENFZaCk85RXNvRVRGS2VMaEVUUWpKWGhRTkhyZ3ZEckxNT1UrYThzUjhNOEJQL01zelUrbURRSURBUUFCTUEwR0NTcUcKU0liM0RRRUJDd1VBQTRJQ0FRQm1CY0FISm9iMXJUV2JTOUxRZEZPT2ZTYXR5bXc5UkRjZncya1k1UllobmFJbQpsZFJ6ZDMwUnQyRUp5YnV3V2NJSXJYKzMvM2pZNkQ2cmhMUkRJK2xMNExHYXdXVk9JMGNwakl6QWMrbm0yYisxCnJwelV1bjZPUm5IaUIvVmFQeTlMRWZnMHBSeGVwTWJrY2xOckQ5ODUwK1NWeTZOd2twRmtab2hRQ0FHRnhPRDUKaW5FNDJwWnBabkd1eWVvYmtFZ0todk5tZUtscG1WRUF4ZVdVRUNBRmtEY1I5TWhuUWpCOGk1UnhncVBaVnFabgpPc0Z1MTkvRmh3cHBwTkVzNFdzT0pjT2F3eTlpTG05SE1vdStLeDIzK3JNdCtraEpKai94b25lRkliUXJKbHpkCmFsclRrSm4wOHJLU0U5bGlGNEl6QlVjVkVKc1o3WGNYZE1TcXpkLzZsWXA5MVErUEdscmlHb3ZWRUthYmRkZjQKZzRIMTVnSFJYamp0WllJOW1kQlN5WWI0WkNtVXJsQVEzcmpvSVVqN3pPUDZDQ3E0UjhXNUpsUWM0eWN4MEpwQwpablZNUC9Wc01qd3A5TWE0dWdtWGxtaCt2U0ZJTHlKZCtod21ZNE1wLzduVEVFTUljRUxDRjVUdFU1clFLSGtZCmgvOTFwUmlkTS80MDhnMW5Ja3dqakVJUkNvSE9CUy8wdFV3KzR6bmVlRkZ0S2dRNDZ5clBvZmRhczY3OUlnbVEKd2IxYVpxVVF0KzVueHRnNEt4aHV6akI5Y1o2b2RuMWRrV2NJT2Qxd3VpeHdMSnVmenR1YWd3ekxEMHdFbFhCWAovenZRSnlsdE0wenl3VFBmT01YZXQxaGxLYXhyd3lvQks5ZzFOY3F5OW9jSzN6djlNUDhKZmFIV005WnZiZz09Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0="
var defaultServerURL = "https://1.2.3.4:6443"
var dummyAzureConfig = datamodel.AzureConfig{ClientID: "dummyclientID", ClientSecret: "dummyClientSecret", TenantID: "dummyTenantID", UserAssignedIdentityID: "dummyUserAssignedIdentityID"}

func setExecCredential(dummyPEM, dummyServerURL string) {
	if dummyPEM == "" {
		dummyPEM = defaultPem
	}
	if dummyServerURL == "" {
		dummyServerURL = defaultServerURL
	}

	testExecInfoJSON := `{
		"apiVersion": "client.authentication.k8s.io/v1",
		"kind": "ExecCredential",
		"spec": {
			"cluster": {
				"certificate-authority-data": "` + dummyPEM + `",
				"config": {},
				"insecure-skip-tls-verify": false,
				"proxy-url": "proxyurl",
				"server": "` + dummyServerURL + `",
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

	testExecInfoJSON = strings.ReplaceAll(testExecInfoJSON, "\n", "")
	testExecInfoJSON = strings.ReplaceAll(testExecInfoJSON, "\t", "")
	os.Setenv("KUBERNETES_EXEC_INFO", testExecInfoJSON) // s: "KUBERNETES_EXEC_INFO must be set to retrieve bootstrap token",}
}

var _ = Describe("TLS Bootstrap client tests", func() {
	var (
		mockCtrl           *gomock.Controller
		imdsClient         *mocks.MockImdsClient
		aadClient          *mocks.MockAadClient
		pbClient           *protos_mock.MockAKSBootstrapTokenRequestClient
		tlsBootstrapClient *tlsBootstrapClientImpl
		mockreader         *mocks.MockFileReader
	)

	BeforeEach(func() {
		mockCtrl = gomock.NewController(GinkgoT())
		imdsClient = mocks.NewMockImdsClient(mockCtrl)
		aadClient = mocks.NewMockAadClient(mockCtrl)
		pbClient = protos_mock.NewMockAKSBootstrapTokenRequestClient(mockCtrl)
		mockreader = mocks.NewMockFileReader(mockCtrl)

		pbClient.EXPECT().AKSBootstrapTokenRequestSetConnection(gomock.Any()).Times(1)
		tlsBootstrapClient = &tlsBootstrapClientImpl{
			logger:     testLogger,
			imdsClient: imdsClient,
			aadClient:  aadClient,
			pbClient:   pbClient,
			reader:     mockreader,
		}
	})

	AfterEach(func() {
		os.Setenv("KUBERNETES_EXEC_INFO", "")
	})

	Context("Test GetBootstrapToken", func() {
		It("should return an error when KUBERNETES_EXEC_INFO is missing", func() {
			os.Setenv("KUBERNETES_EXEC_INFO", "")
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			token, err := tlsBootstrapClient.GetBootstrapToken(ctx)
			Expect(token).To(BeEmpty())
			Expect(err).ToNot(BeNil())
			Expect(err.Error()).To(ContainSubstring("KUBERNETES_EXEC_INFO must be set to retrieve bootstrap token"))
		})

		It("should return a new TLS client", func() {
			var opts SecureTLSBootstrapClientOpts
			tlsClient := NewTLSBootstrapClient(testLogger, opts)
			Expect(tlsClient).ToNot(BeNil())
		})

		When("setupClientConnection and getInstanceData are mocked to succeed", func() {
			It("should fail to recieve nonce", func() {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()

				setExecCredential("", "")
				dummyJsonAzureConfig, err := json.Marshal(dummyAzureConfig)
				Expect(err).To(BeNil())
				mockreader.EXPECT().ReadFile(gomock.Any()).Times(1).Return([]byte(dummyJsonAzureConfig), nil)

				aadClient.EXPECT().GetAadToken(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return("spToken", nil).Times(1)
				imdsClient.EXPECT().GetInstanceData(gomock.Any(), gomock.Any()).Times(1).Return(&datamodel.VMSSInstanceData{}, nil)
				pbClient.EXPECT().GetNonce(gomock.Any(), gomock.Any()).Times(1).Return(&pb.NonceResponse{}, errors.New("error"))

				fmt.Println("KUBERNETES_EXEC_INFO:", os.Getenv("KUBERNETES_EXEC_INFO"))
				token, err := tlsBootstrapClient.GetBootstrapToken(ctx)
				Expect(token).To(BeEmpty())
				Expect(err).ToNot(BeNil())
				Expect(err.Error()).To(ContainSubstring("failed to retrieve a nonce"))
			})
		})

		When("GetInstanceData is mocked to fail", func() {
			It("should fail to retrieve instance metadata", func() {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()

				setExecCredential("", "")
				dummyJsonAzureConfig, err := json.Marshal(dummyAzureConfig)
				Expect(err).To(BeNil())
				mockreader.EXPECT().ReadFile(gomock.Any()).Times(1).Return([]byte(dummyJsonAzureConfig), nil)

				aadClient.EXPECT().GetAadToken(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return("spToken", nil).Times(1)
				imdsClient.EXPECT().GetInstanceData(gomock.Any(), gomock.Any()).Times(1).Return(nil, errors.New("error"))

				token, err := tlsBootstrapClient.GetBootstrapToken(ctx)
				Expect(token).To(BeEmpty())
				Expect(err).ToNot(BeNil())
				Expect(err.Error()).To(ContainSubstring("failed to retrieve instance metadata"))
			})
		})

		When("GetNonce and GetAttestedData are mocked to succeed", func() {
			It("should fail to get a token", func() {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()

				setExecCredential("", "")
				dummyJsonAzureConfig, err := json.Marshal(dummyAzureConfig)
				Expect(err).To(BeNil())
				mockreader.EXPECT().ReadFile(gomock.Any()).Times(1).Return([]byte(dummyJsonAzureConfig), nil)

				aadClient.EXPECT().GetAadToken(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return("spToken", nil).Times(1)
				imdsClient.EXPECT().GetInstanceData(gomock.Any(), gomock.Any()).Times(1).Return(&datamodel.VMSSInstanceData{}, nil)
				imdsClient.EXPECT().GetAttestedData(gomock.Any(), gomock.Any(), gomock.Any()).Times(1).Return(&datamodel.VMSSAttestedData{}, nil)
				pbClient.EXPECT().GetNonce(gomock.Any(), gomock.Any()).Times(1).Return(&pb.NonceResponse{}, nil)
				pbClient.EXPECT().GetToken(gomock.Any(), gomock.Any()).Times(1).Return(&pb.TokenResponse{}, errors.New("error"))

				token, err := tlsBootstrapClient.GetBootstrapToken(ctx)
				Expect(token).To(BeEmpty())
				Expect(err).ToNot(BeNil())
				Expect(err.Error()).To(ContainSubstring("failed to retrieve a token"))
			})
		})

		When("GetAttestedData is mocked to fail", func() {
			It("should fail on GetAttesteddata", func() {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()

				setExecCredential("", "")
				dummyJsonAzureConfig, err := json.Marshal(dummyAzureConfig)
				Expect(err).To(BeNil())
				mockreader.EXPECT().ReadFile(gomock.Any()).Times(1).Return([]byte(dummyJsonAzureConfig), nil)

				aadClient.EXPECT().GetAadToken(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return("spToken", nil).Times(1)
				imdsClient.EXPECT().GetInstanceData(gomock.Any(), gomock.Any()).Times(1).Return(&datamodel.VMSSInstanceData{}, nil)
				imdsClient.EXPECT().GetAttestedData(gomock.Any(), gomock.Any(), gomock.Any()).Times(1).Return(nil, errors.New("error"))
				pbClient.EXPECT().GetNonce(gomock.Any(), gomock.Any()).Times(1).Return(&pb.NonceResponse{}, nil)

				token, err := tlsBootstrapClient.GetBootstrapToken(ctx)
				Expect(token).To(BeEmpty())
				Expect(err).ToNot(BeNil())
				Expect(err.Error()).To(ContainSubstring("failed to retrieve attested data"))
			})
		})

		When("PbClientGetToken is mocked to succeed", func() {
			It("should fail to generate new exec credential", func() {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()

				setExecCredential("", "")
				dummyJsonAzureConfig, err := json.Marshal(dummyAzureConfig)
				Expect(err).To(BeNil())
				mockreader.EXPECT().ReadFile(gomock.Any()).Times(1).Return([]byte(dummyJsonAzureConfig), nil)

				aadClient.EXPECT().GetAadToken(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return("spToken", nil).Times(1)
				imdsClient.EXPECT().GetInstanceData(gomock.Any(), gomock.Any()).Times(1).Return(&datamodel.VMSSInstanceData{}, nil)
				imdsClient.EXPECT().GetAttestedData(gomock.Any(), gomock.Any(), gomock.Any()).Times(1).Return(&datamodel.VMSSAttestedData{}, nil)
				pbClient.EXPECT().GetNonce(gomock.Any(), gomock.Any()).Times(1).Return(&pb.NonceResponse{}, nil)
				pbClient.EXPECT().GetToken(gomock.Any(), gomock.Any()).Times(1).Return(&pb.TokenResponse{Token: "", Expiration: "expirationTimestamp"}, nil)

				token, err := tlsBootstrapClient.GetBootstrapToken(ctx)
				Expect(token).To(BeEmpty())
				Expect(err).ToNot(BeNil())
				Expect(err.Error()).To(ContainSubstring("generate new exec credential"))
			})
		})

		When("getExecCredentialWithToken is mocked to succeed", func() {
			It("should return a bootstrap token", func() {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()

				setExecCredential("", "")
				dummyJsonAzureConfig, err := json.Marshal(dummyAzureConfig)
				Expect(err).To(BeNil())
				mockreader.EXPECT().ReadFile(gomock.Any()).Times(1).Return([]byte(dummyJsonAzureConfig), nil)

				aadClient.EXPECT().GetAadToken(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return("spToken", nil).Times(1)
				imdsClient.EXPECT().GetInstanceData(gomock.Any(), gomock.Any()).Times(1).Return(&datamodel.VMSSInstanceData{}, nil)
				imdsClient.EXPECT().GetAttestedData(gomock.Any(), gomock.Any(), gomock.Any()).Times(1).Return(&datamodel.VMSSAttestedData{}, nil)
				pbClient.EXPECT().GetNonce(gomock.Any(), gomock.Any()).Times(1).Return(&pb.NonceResponse{}, nil)
				pbClient.EXPECT().GetToken(gomock.Any(), gomock.Any()).Times(1).Return(&pb.TokenResponse{Token: "token", Expiration: "expirationTimestamp"}, nil)

				token, err := tlsBootstrapClient.GetBootstrapToken(ctx)
				Expect(token).ToNot(BeEmpty())
				Expect(err).To(BeNil())
			})
		})
	})

	Context("Test loadExecCredential", func() {
		When("ExecCredential JSON is properly formed", func() {
			It("should correctly parse and load the exec credential", func() {
				setExecCredential("", "")
				execCredential, err := loadExecCredential()
				Expect(err).To(BeNil())
				Expect(execCredential).ToNot(BeNil())
				Expect(execCredential.APIVersion).To(Equal("client.authentication.k8s.io/v1"))
				Expect(execCredential.Kind).To(Equal("ExecCredential"))
				Expect(execCredential.Spec.Cluster.CertificateAuthorityData).To(Equal(defaultPem))
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

		It("should fail when given an invalid server URL", func() {
			execCredential := &datamodel.ExecCredential{}
			execCredential.Spec.Cluster.Server = ":invalidurl.com"
			serverURL, err := getServerURL(execCredential)
			Expect(err).ToNot(BeNil())
			Expect(err.Error()).To(ContainSubstring("failed to parse server URL"))
			Expect(serverURL).To(BeEmpty())
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
				setExecCredential("YW55IGNhcm5hbCBwbGVhc3U======", "")
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()

				conn, err := tlsBootstrapClient.setupClientConnection(ctx)
				Expect(conn).To(BeNil())
				Expect(err).ToNot(BeNil())
				Expect(err.Error()).To(ContainSubstring("failed to decode"))
			})
		})

		When("loadExecCredential is mocked to succeed", func() {
			It("should fail on getTLSConfig", func() {
				setExecCredential("SGVsbG8gV29ybGQh", "")
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()

				customDummyAzureConfig := datamodel.AzureConfig{}
				dummyJsonAzureConfig, err := json.Marshal(customDummyAzureConfig)
				Expect(err).To(BeNil())
				mockreader.EXPECT().ReadFile(gomock.Any()).Times(1).Return([]byte(dummyJsonAzureConfig), nil)

				conn, err := tlsBootstrapClient.setupClientConnection(ctx)
				Expect(conn).To(BeNil())
				Expect(err).ToNot(BeNil())
				Expect(err.Error()).To(ContainSubstring("failed to get TLS config"))
			})
		})

		When("getTlsConfig is mocked to succeed", func() {
			It("should fail on loadAzureJson", func() {
				setExecCredential("", "")
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()

				mockreader.EXPECT().ReadFile(gomock.Any()).Times(1).Return(nil, errors.New("error"))

				conn, err := tlsBootstrapClient.setupClientConnection(ctx)
				Expect(conn).To(BeNil())
				Expect(err).ToNot(BeNil())
				Expect(err.Error()).To(ContainSubstring("failed to parse azure"))
			})
		})

		When("getAuthToken is mocked to succeed", func() {
			It("setupClientConnection should succeed", func() {
				setExecCredential("", "")
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()

				dummyJsonAzureConfig, err := json.Marshal(dummyAzureConfig)
				Expect(err).To(BeNil())
				mockreader.EXPECT().ReadFile(gomock.Any()).Times(1).Return([]byte(dummyJsonAzureConfig), nil)
				aadClient.EXPECT().GetAadToken(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return("spToken", nil).Times(1)

				conn, err := tlsBootstrapClient.setupClientConnection(ctx)
				Expect(conn).ToNot(BeNil())
				Expect(err).To(BeNil())
			})
		})

		When("getAuthToken is mocked to fail", func() {
			It("should fail on getAuthToken", func() {
				setExecCredential("", "")
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()

				dummyJsonAzureConfig, err := json.Marshal(dummyAzureConfig)
				Expect(err).To(BeNil())
				mockreader.EXPECT().ReadFile(gomock.Any()).Times(1).Return([]byte(dummyJsonAzureConfig), nil)
				aadClient.EXPECT().GetAadToken(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return("", errors.New("error")).Times(1)

				conn, err := tlsBootstrapClient.setupClientConnection(ctx)
				Expect(conn).To(BeNil())
				Expect(err).ToNot(BeNil())
				Expect(err.Error()).To(ContainSubstring("unable to get SPN"))
			})
		})

		When("getServerURL is mocked to fail", func() {
			It("should fail on getServerURL", func() {
				setExecCredential("", ":invalidurl.com")
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()

				dummyJsonAzureConfig, err := json.Marshal(dummyAzureConfig)
				Expect(err).To(BeNil())
				mockreader.EXPECT().ReadFile(gomock.Any()).Times(1).Return([]byte(dummyJsonAzureConfig), nil)
				aadClient.EXPECT().GetAadToken(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return("spToken", nil).Times(1)

				conn, err := tlsBootstrapClient.setupClientConnection(ctx)
				Expect(conn).To(BeNil())
				Expect(err).ToNot(BeNil())
				Expect(err.Error()).To(ContainSubstring("failed to parse server URL"))
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

		When("There is no timestamp given", func() {
			cred, err := getExecCredentialWithToken("dummyToken", "")
			Expect(err).ToNot(BeNil())
			Expect(err.Error()).To(ContainSubstring("token expiration timestamp is empty"))
			Expect(cred).To(BeNil())
		})
	})
})
