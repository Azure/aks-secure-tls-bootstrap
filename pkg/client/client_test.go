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

	mocks "github.com/Azure/aks-tls-bootstrap-client/pkg/client/mocks"
	"github.com/Azure/aks-tls-bootstrap-client/pkg/datamodel"
	secureTLSBootstrapService "github.com/Azure/aks-tls-bootstrap-client/service/protos"
	mocks_secureTLSBootstrapService "github.com/Azure/aks-tls-bootstrap-client/service/protos/mocks"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"go.uber.org/mock/gomock"
	"go.uber.org/zap"
)

const (
	emptyJSON = `{}`

	exampleCACert = `-----BEGIN CERTIFICATE-----
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

	mockExecCredentialTemplate = `
{
	"apiVersion": "client.authentication.k8s.io/v1",
	"kind": "ExecCredential",
	"spec": {
		"cluster": {
			"certificate-authority-data": "%[1]s",
			"config": {},
			"insecure-skip-tls-verify": false,
			"proxy-url": "proxyurl",
			"server": "%[2]s",
			"tls-server-name": "someserver"
		},
		"interactive": false
	},
	"status": {
		"clientCertificateData": "certdata",
		"clientKeyData": "keydata"
	}
}`

	defaultMockServerURL = "https://1.2.3.4:6443"

	defaultMockEncodedCAData = "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUZtakNDQTRJQ0NRQ0d3OEVzRExCNEl6QU5CZ2txaGtpRzl3MEJBUXNGQURDQmpqRUxNQWtHQTFVRUJoTUMKVlZNeE" +
		"V6QVJCZ05WQkFnTUNsZGhjMmhwYm1kMGIyNHhFREFPQmdOVkJBY01CMU5sWVhSMGJHVXhFakFRQmdOVgpCQW9NQ1UxcFkzSnZjMjltZERFUk1BOEdBMVVFQ3d3SVRtOWtaU0JUYVdjeERUQUxCZ05WQ" +
		"kFNTUJHaHZjM1F4CklqQWdCZ2txaGtpRzl3MEJDUUVXRTJSMWJXMTVRRzFwWTNKdmMyOW1kQzVqYjIwd0hoY05Nak14TURJMk1qQXkKTkRJeVdoY05NalF4TURJMU1qQXlOREl5V2pDQmpqRUxNQWtH" +
		"QTFVRUJoTUNWVk14RXpBUkJnTlZCQWdNQ2xkaApjMmhwYm1kMGIyNHhFREFPQmdOVkJBY01CMU5sWVhSMGJHVXhFakFRQmdOVkJBb01DVTFwWTNKdmMyOW1kREVSCk1BOEdBMVVFQ3d3SVRtOWtaU0J" +
		"UYVdjeERUQUxCZ05WQkFNTUJHaHZjM1F4SWpBZ0Jna3Foa2lHOXcwQkNRRVcKRTJSMWJXMTVRRzFwWTNKdmMyOW1kQzVqYjIwd2dnSWlNQTBHQ1NxR1NJYjNEUUVCQVFVQUE0SUNEd0F3Z2dJSwpBb0" +
		"lDQVFEWHp3Mytsb3NDY0IwbXJaSmg2aDZkaDVUYVdhK09hOHNpQTJsaUtFdDl6MXo0b2RYZVkxR3VTeTZkCnNienZ0RW1EVkR1QnBZM2lkaXQ0YVE4VHEzK2hMNnRTUUFXMkt5OG5ZU0YrMnMxRHBJc" +
		"Fg4TlJHbStyQ2hUNXEKOWpCY2pGUUIxdDdWTWZZd3hNL1RWQ3VuL0EvWjRIOUI1Sm9zc3BHdURMYjNEMzhUNDZRMmRsa3h6ODNMUVpONApscWM3cGJ4QlBRQk50TlF0WnhNNFZpRU1hdTV0Z293TlBI" +
		"OG1MSHExMHpQS3pGMWE4b1R5Tnp4KzAyY0s3WVR1CjVFWTFwRDhLQnhlLzRrRjFKOGdsWFJmUFpEaTRmcG1QSUlCRFRSTmcvUmtmTFhRelRZL2RtOHZwcUZSaGgwdHQKZEZEdVRYRkFIWkJFTkZYMFd" +
		"VS3ZhNXNLbVhuUW9ieS9GRGp1UGJtUmNvVjlEMC9hQnJVVG05bS8rZ05aa3BzMQplNTJreVBjSnJ2ZkhMdjdCTDI0cy9RQjhKMmlKYms2MHh4eUYzcUx1K2k4OE52anNScHVMb3QrTVYxNGFnc1VXCn" +
		"dhaXEvbHdXMjg1TGE4MUttak9WcEs0WHZ3VFJSRG5JZkZUcW9pMTJ2TllCaVphMVNnQUxUeWNVd1J0YU1NTE8KOE56U25FdHNIWWdBVnVKdTE3dUJiMDIyeGl5SU9VR0xSU2dUZnJoSHFjVklsQ0Fkd" +
		"zhwMnhRdjI2dDdVdTNBYwppRHlhQ2s2V1hyTTFhVGNSUzFWYS85ZnlWWmtJZEtNVGFpNHVJOEJzbXZtOGUwakJtRGF1Zyt5VWxDdmVENFZaCk85RXNvRVRGS2VMaEVUUWpKWGhRTkhyZ3ZEckxNT1Ur" +
		"YThzUjhNOEJQL01zelUrbURRSURBUUFCTUEwR0NTcUcKU0liM0RRRUJDd1VBQTRJQ0FRQm1CY0FISm9iMXJUV2JTOUxRZEZPT2ZTYXR5bXc5UkRjZncya1k1UllobmFJbQpsZFJ6ZDMwUnQyRUp5YnV" +
		"3V2NJSXJYKzMvM2pZNkQ2cmhMUkRJK2xMNExHYXdXVk9JMGNwakl6QWMrbm0yYisxCnJwelV1bjZPUm5IaUIvVmFQeTlMRWZnMHBSeGVwTWJrY2xOckQ5ODUwK1NWeTZOd2twRmtab2hRQ0FHRnhPRD" +
		"UKaW5FNDJwWnBabkd1eWVvYmtFZ0todk5tZUtscG1WRUF4ZVdVRUNBRmtEY1I5TWhuUWpCOGk1UnhncVBaVnFabgpPc0Z1MTkvRmh3cHBwTkVzNFdzT0pjT2F3eTlpTG05SE1vdStLeDIzK3JNdCtra" +
		"EpKai94b25lRkliUXJKbHpkCmFsclRrSm4wOHJLU0U5bGlGNEl6QlVjVkVKc1o3WGNYZE1TcXpkLzZsWXA5MVErUEdscmlHb3ZWRUthYmRkZjQKZzRIMTVnSFJYamp0WllJOW1kQlN5WWI0WkNtVXJs" +
		"QVEzcmpvSVVqN3pPUDZDQ3E0UjhXNUpsUWM0eWN4MEpwQwpablZNUC9Wc01qd3A5TWE0dWdtWGxtaCt2U0ZJTHlKZCtod21ZNE1wLzduVEVFTUljRUxDRjVUdFU1clFLSGtZCmgvOTFwUmlkTS80MDh" +
		"nMW5Ja3dqakVJUkNvSE9CUy8wdFV3KzR6bmVlRkZ0S2dRNDZ5clBvZmRhczY3OUlnbVEKd2IxYVpxVVF0KzVueHRnNEt4aHV6akI5Y1o2b2RuMWRrV2NJT2Qxd3VpeHdMSnVmenR1YWd3ekxEMHdFbF" +
		"hCWAovenZRSnlsdE0wenl3VFBmT01YZXQxaGxLYXhyd3lvQks5ZzFOY3F5OW9jSzN6djlNUDhKZmFIV005WnZiZz09Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0="
)

var (
	mockPEMCAs = []byte(exampleCACert)

	defaultMockAzureConfig = datamodel.AzureConfig{
		ClientID:               "clientId",
		ClientSecret:           "clientSecret",
		TenantID:               "tenantId",
		UserAssignedIdentityID: "userAssignedIdentityId",
	}

	defaultMockAzureConfigBytes, _ = json.Marshal(defaultMockAzureConfig)
)

func setDefaultMockExecCredential() {
	setMockExecCredential(defaultMockEncodedCAData, defaultMockServerURL)
}

func setMockExecCredential(dummyPEM, dummyServerURL string) {
	rawExecCredential := fmt.Sprintf(mockExecCredentialTemplate, dummyPEM, dummyServerURL)
	rawExecCredential = strings.ReplaceAll(rawExecCredential, "\n", "")
	rawExecCredential = strings.ReplaceAll(rawExecCredential, "\t", "")
	os.Setenv(kubernetesExecInfoVarName, rawExecCredential)
}

func getDefaultMockExecCredential() *datamodel.ExecCredential {
	return getMockExecCredential(defaultMockEncodedCAData, defaultMockServerURL)
}

func getMockExecCredential(pem, serverURL string) *datamodel.ExecCredential {
	credential := &datamodel.ExecCredential{
		APIVersion: "client.authentication.k8s.io/v1",
		Kind:       "ExecCredential",
		Status: datamodel.ExecCredentialStatus{
			ClientCertificateData: "certdata",
			ClientKeyData:         "keydata",
		},
	}
	credential.Spec.Cluster.CertificateAuthorityData = pem
	credential.Spec.Cluster.InsecureSkipTLSVerify = false
	credential.Spec.Cluster.ProxyURL = "proxyurl"
	credential.Spec.Cluster.Server = serverURL
	credential.Spec.Cluster.TLSServerName = "someserver"
	return credential
}

type mockClientConn struct{}

func (cc *mockClientConn) Close() error {
	return nil
}

var _ = Describe("TLS Bootstrap client tests", func() {
	var (
		mockCtrl           *gomock.Controller
		imdsClient         *mocks.MockImdsClient
		aadClient          *mocks.MockAadClient
		serviceClient      *mocks_secureTLSBootstrapService.MockSecureTLSBootstrapServiceClient
		tlsBootstrapClient *tlsBootstrapClientImpl
		mockReader         *mocks.MockfileReader
	)

	AfterEach(func() {
		os.Setenv(kubernetesExecInfoVarName, "")
	})

	Context("NewTLSBootstrapClient tests", func() {
		It("should return a new TLS bootstrap client", func() {
			bootstrapClient := NewTLSBootstrapClient(testLogger, SecureTLSBootstrapClientOpts{})
			Expect(bootstrapClient).ToNot(BeNil())
		})
	})

	Context("GetBootstrapToken tests", func() {
		BeforeEach(func() {
			mockCtrl = gomock.NewController(GinkgoT())
			imdsClient = mocks.NewMockImdsClient(mockCtrl)
			aadClient = mocks.NewMockAadClient(mockCtrl)
			mockReader = mocks.NewMockfileReader(mockCtrl)
			serviceClient = mocks_secureTLSBootstrapService.NewMockSecureTLSBootstrapServiceClient(mockCtrl)

			tlsBootstrapClient = &tlsBootstrapClientImpl{
				logger:     testLogger,
				imdsClient: imdsClient,
				aadClient:  aadClient,
				reader:     mockReader,
			}
			tlsBootstrapClient.serviceClientFactory = func(
				ctx context.Context,
				logger *zap.Logger,
				opts serviceClientFactoryOpts) (secureTLSBootstrapService.SecureTLSBootstrapServiceClient, grpcClientConn, error) {
				return serviceClient, new(mockClientConn), nil
			}
		})

		AfterEach(func() {
			mockCtrl.Finish()
		})

		When("KUBERNETES_EXEC_INFO env var is unset", func() {
			It("should return an error", func() {
				os.Setenv(kubernetesExecInfoVarName, "")
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()

				token, err := tlsBootstrapClient.GetBootstrapToken(ctx)
				Expect(token).To(BeEmpty())
				Expect(err).ToNot(BeNil())
				Expect(err.Error()).To(ContainSubstring("KUBERNETES_EXEC_INFO must be set to retrieve bootstrap token"))
			})
		})

		When("azure config is empty", func() {
			It("should return an error", func() {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				setDefaultMockExecCredential()
				mockReader.EXPECT().ReadFile(gomock.Any()).
					Return([]byte(emptyJSON), nil).
					Times(1)

				token, err := tlsBootstrapClient.GetBootstrapToken(ctx)
				Expect(token).To(BeEmpty())
				Expect(err).ToNot(BeNil())
				Expect(err.Error()).To(ContainSubstring("unable to infer node identity type: client ID in azure.json is empty"))
			})
		})

		When("an auth token cannot be retrieved", func() {
			It("return an error", func() {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				setDefaultMockExecCredential()
				mockReader.EXPECT().ReadFile(gomock.Any()).
					Return(defaultMockAzureConfigBytes, nil).
					Times(1)
				aadClient.EXPECT().GetAadToken(gomock.Any(), gomock.Any(), gomock.Any()).
					Return("", errors.New("cannot retrieve AAD token")).
					Times(1)

				token, err := tlsBootstrapClient.GetBootstrapToken(ctx)
				Expect(token).To(BeEmpty())
				Expect(err).ToNot(BeNil())
				Expect(err.Error()).To(ContainSubstring("unable to get SPN"))
				Expect(err.Error()).To(ContainSubstring("cannot retrieve AAD token"))
			})
		})

		When("unable to retrieve instance data from IMDS", func() {
			It("should return an error", func() {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				setDefaultMockExecCredential()
				mockReader.EXPECT().ReadFile(gomock.Any()).
					Return(defaultMockAzureConfigBytes, nil).
					Times(1)
				aadClient.EXPECT().GetAadToken(gomock.Any(), gomock.Any(), gomock.Any()).
					Return("spToken", nil).
					Times(1)
				imdsClient.EXPECT().GetInstanceData(gomock.Any(), gomock.Any()).
					Return(nil, errors.New("cannot get VM instance data from IMDS")).
					Times(1)

				token, err := tlsBootstrapClient.GetBootstrapToken(ctx)
				Expect(token).To(BeEmpty())
				Expect(err).ToNot(BeNil())
				Expect(err.Error()).To(ContainSubstring("failed to retrieve instance metadata"))
				Expect(err.Error()).To(ContainSubstring("cannot get VM instance data from IMDS"))
			})
		})

		When("unable to retrieve nonce from bootstrap server", func() {
			It("should return an error", func() {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				setDefaultMockExecCredential()
				mockReader.EXPECT().ReadFile(gomock.Any()).
					Return(defaultMockAzureConfigBytes, nil).
					Times(1)
				aadClient.EXPECT().GetAadToken(gomock.Any(), gomock.Any(), gomock.Any()).
					Return("spToken", nil).
					Times(1)
				imdsClient.EXPECT().GetInstanceData(gomock.Any(), gomock.Any()).
					Return(&datamodel.VMSSInstanceData{}, nil).
					Times(1)
				serviceClient.EXPECT().GetNonce(gomock.Any(), gomock.Any()).
					Return(&secureTLSBootstrapService.NonceResponse{}, errors.New("cannot get nonce response")).
					Times(1)

				token, err := tlsBootstrapClient.GetBootstrapToken(ctx)
				Expect(token).To(BeEmpty())
				Expect(err).ToNot(BeNil())
				Expect(err.Error()).To(ContainSubstring("failed to retrieve a nonce from bootstrap server"))
				Expect(err.Error()).To(ContainSubstring("cannot get nonce response"))
			})
		})

		When("unable to retrieve attested data from IMDS", func() {
			It("should return an error", func() {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				setDefaultMockExecCredential()
				mockReader.EXPECT().ReadFile(gomock.Any()).
					Return(defaultMockAzureConfigBytes, nil).
					Times(1)
				aadClient.EXPECT().GetAadToken(gomock.Any(), gomock.Any(), gomock.Any()).
					Return("spToken", nil).
					Times(1)
				imdsClient.EXPECT().GetInstanceData(gomock.Any(), gomock.Any()).
					Return(&datamodel.VMSSInstanceData{}, nil).
					Times(1)
				imdsClient.EXPECT().GetAttestedData(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(nil, errors.New("cannot get VM attested data")).
					Times(1)
				serviceClient.EXPECT().GetNonce(gomock.Any(), gomock.Any()).
					Return(&secureTLSBootstrapService.NonceResponse{}, nil).
					Times(1)

				token, err := tlsBootstrapClient.GetBootstrapToken(ctx)
				Expect(token).To(BeEmpty())
				Expect(err).ToNot(BeNil())
				Expect(err.Error()).To(ContainSubstring("failed to retrieve attested data"))
				Expect(err.Error()).To(ContainSubstring("cannot get VM attested data"))
			})
		})

		When("unable to retrieve a TLS bootstrap token from the server", func() {
			It("should return an error", func() {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				setDefaultMockExecCredential()
				mockReader.EXPECT().ReadFile(gomock.Any()).
					Return(defaultMockAzureConfigBytes, nil).
					Times(1)
				aadClient.EXPECT().GetAadToken(gomock.Any(), gomock.Any(), gomock.Any()).
					Return("spToken", nil).
					Times(1)
				imdsClient.EXPECT().GetInstanceData(gomock.Any(), gomock.Any()).
					Return(&datamodel.VMSSInstanceData{}, nil).
					Times(1)
				imdsClient.EXPECT().GetAttestedData(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(&datamodel.VMSSAttestedData{}, nil).
					Times(1)
				serviceClient.EXPECT().GetNonce(gomock.Any(), gomock.Any()).
					Return(&secureTLSBootstrapService.NonceResponse{}, nil).
					Times(1)
				serviceClient.EXPECT().GetToken(gomock.Any(), gomock.Any()).
					Return(&secureTLSBootstrapService.TokenResponse{}, errors.New("cannot get bootstrap token from server")).
					Times(1)

				token, err := tlsBootstrapClient.GetBootstrapToken(ctx)
				Expect(token).To(BeEmpty())
				Expect(err).ToNot(BeNil())
				Expect(err.Error()).To(ContainSubstring("failed to retrieve a new TLS bootstrap token from the bootstrap server"))
				Expect(err.Error()).To(ContainSubstring("cannot get bootstrap token from server"))
			})
		})

		When("server responds with an invalid bootstrap token", func() {
			It("should fail to create a new exec credential and return an error", func() {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				setDefaultMockExecCredential()
				mockReader.EXPECT().ReadFile(gomock.Any()).
					Return(defaultMockAzureConfigBytes, nil).
					Times(1)
				aadClient.EXPECT().GetAadToken(gomock.Any(), gomock.Any(), gomock.Any()).
					Return("spToken", nil).
					Times(1)
				imdsClient.EXPECT().GetInstanceData(gomock.Any(), gomock.Any()).
					Return(&datamodel.VMSSInstanceData{}, nil).
					Times(1)
				imdsClient.EXPECT().GetAttestedData(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(&datamodel.VMSSAttestedData{}, nil).
					Times(1)
				serviceClient.EXPECT().GetNonce(gomock.Any(), gomock.Any()).
					Return(&secureTLSBootstrapService.NonceResponse{}, nil).
					Times(1)
				serviceClient.EXPECT().GetToken(gomock.Any(), gomock.Any()).
					Return(&secureTLSBootstrapService.TokenResponse{Token: "", Expiration: "expirationTimestamp"}, nil).
					Times(1)

				token, err := tlsBootstrapClient.GetBootstrapToken(ctx)
				Expect(token).To(BeEmpty())
				Expect(err).ToNot(BeNil())
				Expect(err.Error()).To(ContainSubstring("unable to generate new exec credential with bootstrap token"))
				Expect(err.Error()).To(ContainSubstring("token string is empty, cannot generate exec credential"))
			})
		})

		When("getExecCredentialWithToken is mocked to succeed", func() {
			It("should return a bootstrap token", func() {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				setDefaultMockExecCredential()
				mockReader.EXPECT().ReadFile(gomock.Any()).
					Return(defaultMockAzureConfigBytes, nil).
					Times(1)
				aadClient.EXPECT().GetAadToken(gomock.Any(), gomock.Any(), gomock.Any()).
					Return("spToken", nil).
					Times(1)
				imdsClient.EXPECT().GetInstanceData(gomock.Any(), gomock.Any()).
					Return(&datamodel.VMSSInstanceData{}, nil).
					Times(1)
				imdsClient.EXPECT().GetAttestedData(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(&datamodel.VMSSAttestedData{}, nil).
					Times(1)
				serviceClient.EXPECT().GetNonce(gomock.Any(), gomock.Any()).
					Return(&secureTLSBootstrapService.NonceResponse{}, nil).
					Times(1)
				serviceClient.EXPECT().GetToken(gomock.Any(), gomock.Any()).
					Return(&secureTLSBootstrapService.TokenResponse{Token: "secure.bootstraptoken", Expiration: "expirationTimestamp"}, nil).
					Times(1)

				execCredentialWithToken, err := tlsBootstrapClient.GetBootstrapToken(ctx)
				Expect(err).To(BeNil())
				Expect(execCredentialWithToken).ToNot(BeEmpty())
				Expect(execCredentialWithToken).To(ContainSubstring("client.authentication.k8s.io/v1"))
				Expect(execCredentialWithToken).To(ContainSubstring("ExecCredential"))
				Expect(execCredentialWithToken).To(ContainSubstring(`"token":"secure.bootstraptoken"`))
			})
		})
	})

	Context("loadExecCredential tests", func() {
		When("exec credential JSON is malformed", func() {
			It("should return an error", func() {
				os.Setenv(kubernetesExecInfoVarName, malformedJSON)
				execCredential, err := loadExecCredential()
				Expect(execCredential).To(BeNil())
				Expect(err).ToNot(BeNil())
				Expect(err.Error()).To(ContainSubstring("unable to parse KUBERNETES_EXEC_INFO data"))
			})
		})

		When("the exec credential is properly formed", func() {
			It("should correctly parse and load the exec credential", func() {
				setDefaultMockExecCredential()
				execCredential, err := loadExecCredential()
				Expect(err).To(BeNil())
				Expect(execCredential).ToNot(BeNil())
				Expect(execCredential.APIVersion).To(Equal("client.authentication.k8s.io/v1"))
				Expect(execCredential.Kind).To(Equal("ExecCredential"))
				Expect(execCredential.Spec.Cluster.CertificateAuthorityData).To(Equal(defaultMockEncodedCAData))
				Expect(execCredential.Spec.Cluster.InsecureSkipTLSVerify).To(BeFalse())
				Expect(execCredential.Spec.Cluster.ProxyURL).To(Equal("proxyurl"))
				Expect(execCredential.Spec.Cluster.Server).To(Equal("https://1.2.3.4:6443"))
				Expect(execCredential.Spec.Cluster.TLSServerName).To(Equal("someserver"))
				Expect(execCredential.Spec.Interactive).To(BeFalse())
				Expect(execCredential.Status.ClientCertificateData).To(Equal("certdata"))
				Expect(execCredential.Status.ClientKeyData).To(Equal("keydata"))
				Expect(execCredential.Status.Token).To(BeEmpty())
			})
		})
	})

	Context("getServerURL tests", func() {
		When("the server URL is invalid", func() {
			It("should return an error", func() {
				execCredential := &datamodel.ExecCredential{}
				execCredential.Spec.Cluster.Server = ":invalidurl.com"
				serverURL, err := getServerURL(execCredential)
				Expect(serverURL).To(BeEmpty())
				Expect(err).ToNot(BeNil())
				Expect(err.Error()).To(ContainSubstring("failed to parse server URL"))
			})
		})

		When("the server URL is valid", func() {
			It("should correctly join server name and port with a ':'", func() {
				execCredential := &datamodel.ExecCredential{}
				execCredential.Spec.Cluster.Server = defaultMockServerURL
				serverURL, err := getServerURL(execCredential)
				Expect(err).To(BeNil())
				Expect(serverURL).To(Equal("1.2.3.4:6443"))
			})
		})
	})

	Context("getTLSConfig tests", func() {
		var poolWithCACert *x509.CertPool

		BeforeEach(func() {
			poolWithCACert = x509.NewCertPool()
			ok := poolWithCACert.AppendCertsFromPEM(mockPEMCAs)
			Expect(ok).To(BeTrue())
		})

		When("nextProto is not supplied", func() {
			It("should not include NextProtos in returned config", func() {
				config, err := getTLSConfig(mockPEMCAs, "", false)
				Expect(err).To(BeNil())
				Expect(config).ToNot(BeNil())
				Expect(config.NextProtos).To(BeNil())
				Expect(config.InsecureSkipVerify).To(BeFalse())
				Expect(config.RootCAs.Equal(poolWithCACert)).To(BeTrue())
			})
		})

		When("nextProto is supplied", func() {
			It("should include NextProtos in returned config", func() {
				config, err := getTLSConfig(mockPEMCAs, "bootstrap", false)
				Expect(err).To(BeNil())
				Expect(config).NotTo(BeNil())
				Expect(config.NextProtos).NotTo(BeNil())
				Expect(config.NextProtos).To(Equal([]string{"bootstrap", "h2"}))
				Expect(config.InsecureSkipVerify).To(BeFalse())
				Expect(config.RootCAs.Equal(poolWithCACert)).To(BeTrue())
			})
		})

		When("insecureSkipVerify is false", func() {
			It("should return config with false value of InsecureSkipVerify", func() {
				config, err := getTLSConfig(mockPEMCAs, "nextProto", false)
				Expect(err).To(BeNil())
				Expect(config).NotTo(BeNil())
				Expect(config.InsecureSkipVerify).To(BeFalse())
				Expect(config.RootCAs.Equal(poolWithCACert)).To(BeTrue())
			})
		})

		When("insecureSkipVerify is true", func() {
			It("should return config with true value of InsecureSkipVerify", func() {
				config, err := getTLSConfig(mockPEMCAs, "nextProto", true)
				Expect(err).To(BeNil())
				Expect(config).NotTo(BeNil())
				Expect(config.InsecureSkipVerify).To(BeTrue())
				Expect(config.RootCAs.Equal(poolWithCACert)).To(BeTrue())
			})
		})
	})

	Context("getExecCredentialWithToken tests", func() {
		When("token and timestamp strings are non-empty", func() {
			It("should return an exec credential without error", func() {
				cred, err := getExecCredentialWithToken("token", "timestamp")
				Expect(err).To(BeNil())
				Expect(cred).ToNot(BeNil())
				Expect(cred.Status.Token).To(Equal("token"))
				Expect(cred.Status.ExpirationTimestamp).To(Equal("timestamp"))
			})
		})

		When("token string is empty", func() {
			It("should return an error", func() {
				cred, err := getExecCredentialWithToken("", "timestamp")
				Expect(cred).To(BeNil())
				Expect(err).ToNot(BeNil())
				Expect(err.Error()).To(ContainSubstring("token string is empty, cannot generate exec credential"))
			})
		})

		When("There is no timestamp given", func() {
			It("should return an error", func() {
				cred, err := getExecCredentialWithToken("token", "")
				Expect(cred).To(BeNil())
				Expect(err).ToNot(BeNil())
				Expect(err.Error()).To(ContainSubstring("token expiration timestamp is empty"))
			})
		})
	})
})
