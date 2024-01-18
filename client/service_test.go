package client

import (
	"context"

	"github.com/Azure/aks-tls-bootstrap-client/client/pkg/datamodel"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"google.golang.org/grpc/test/bufconn"
)

const (
	mockNextProto = "nextProto"
)

var _ = Describe("Secure TLS Bootstrap Client service factory tests", func() {
	Context("setupClientConnection tests", func() {
		var tlsBootstrapClient *tlsBootstrapClientImpl

		BeforeEach(func() {
			tlsBootstrapClient = &tlsBootstrapClientImpl{
				logger: testLogger,
			}
		})

		When("KUBERNETES_EXEC_INFO cluster CA data is malformed", func() {
			It("should return an error", func() {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				badCAData := "YW55IGNhcm5hbCBwbGVhc3U======"
				credential := &datamodel.ExecCredential{}
				credential.Spec.Cluster.CertificateAuthorityData = badCAData

				serviceClient, conn, err := secureTLSBootstrapServiceClientFactory(ctx, testLogger, serviceClientFactoryOpts{
					execCredential: credential,
					nextProto:      mockNextProto,
				})
				Expect(serviceClient).To(BeNil())
				Expect(conn).To(BeNil())
				Expect(err).ToNot(BeNil())
				Expect(err.Error()).To(ContainSubstring("failed to decode base64 cluster certificates"))
			})
		})

		When("ca data is invalid", func() {
			It("should return an error", func() {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				credential := &datamodel.ExecCredential{}
				credential.Spec.Cluster.CertificateAuthorityData = "SGVsbG8gV29ybGQh"
				credential.Spec.Cluster.Server = defaultMockServerURL
				tlsBootstrapClient.azureConfig = &datamodel.AzureConfig{}

				serviceClient, conn, err := secureTLSBootstrapServiceClientFactory(ctx, testLogger, serviceClientFactoryOpts{
					execCredential: credential,
					nextProto:      mockNextProto,
				})
				Expect(serviceClient).To(BeNil())
				Expect(conn).To(BeNil())
				Expect(err).ToNot(BeNil())
				Expect(err.Error()).To(ContainSubstring("failed to get TLS config"))
				Expect(err.Error()).To(ContainSubstring("failed to load cluster root CA(s)"))
			})
		})

		When("the server URL is invalid", func() {
			It("should return an error", func() {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				credential := getMockExecCredential(defaultMockEncodedCAData, ":invalidurl.com")

				serviceClient, conn, err := secureTLSBootstrapServiceClientFactory(ctx, testLogger, serviceClientFactoryOpts{
					execCredential: credential,
					nextProto:      mockNextProto,
					authToken:      "spToken",
				})
				Expect(serviceClient).To(BeNil())
				Expect(conn).To(BeNil())
				Expect(err).ToNot(BeNil())
				Expect(err.Error()).To(ContainSubstring("failed to parse server URL"))
			})
		})

		When("an auth token can be generated and client connection can be created", func() {
			It("should create the connection without error", func() {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				lis := bufconn.Listen(1024)
				defer lis.Close()
				credential := getDefaultMockExecCredential()
				credential.Spec.Cluster.Server = lis.Addr().String()

				serviceClient, conn, err := secureTLSBootstrapServiceClientFactory(ctx, testLogger, serviceClientFactoryOpts{
					execCredential: credential,
					nextProto:      mockNextProto,
				})
				defer conn.Close()

				Expect(err).To(BeNil())
				Expect(conn).ToNot(BeNil())
				Expect(serviceClient).ToNot(BeNil())
			})
		})
	})
})
