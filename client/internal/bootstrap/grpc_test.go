// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package bootstrap

import (
	"crypto/x509"
	"os"
	"path/filepath"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"go.uber.org/zap"
	"google.golang.org/grpc/test/bufconn"

	"github.com/Azure/aks-secure-tls-bootstrap/client/internal/testutil"
)

var _ = Describe("grpc", Ordered, func() {
	var (
		clusterCACertPEM []byte
		logger           *zap.Logger
	)

	BeforeAll(func() {
		logger, _ = zap.NewDevelopment()

		var err error
		clusterCACertPEM, _, err = testutil.GenerateCertPEMWithExpiration(testutil.CertTemplate{
			CommonName:   "hcp",
			Organization: "aks",
			IsCA:         true,
			Expiration:   time.Now().Add(time.Hour),
		})
		Expect(err).To(BeNil())
	})

	Context("secureTLSBootstrapServiceClientFactory", func() {
		When("cluster ca data cannot be read", func() {
			It("should return an error", func() {
				serviceClient, close, err := serviceClientFactory(logger, "token", &Config{
					ClusterCAFilePath: "does/not/exist.crt",
					NextProto:         "nextProto",
					APIServerFQDN:     "fqdn",
				})

				Expect(serviceClient).To(BeNil())
				Expect(close).To(BeNil())
				Expect(err).ToNot(BeNil())
				Expect(err.Error()).To(ContainSubstring("reading cluster CA data from does/not/exist.crt"))

			})
		})
		When("cluster ca data is invalid", func() {
			It("should return an error", func() {
				tempDir := GinkgoT().TempDir()
				caFilePath := filepath.Join(tempDir, "ca.crt")
				err := os.WriteFile(caFilePath, []byte("SGVsbG8gV29ybGQh"), os.ModePerm)
				Expect(err).To(BeNil())

				serviceClient, close, err := serviceClientFactory(logger, "token", &Config{
					ClusterCAFilePath: caFilePath,
					NextProto:         "nextProto",
					APIServerFQDN:     "fqdn",
				})

				Expect(serviceClient).To(BeNil())
				Expect(close).To(BeNil())
				Expect(err).ToNot(BeNil())
				Expect(err.Error()).To(ContainSubstring("failed to get TLS config"))
				Expect(err.Error()).To(ContainSubstring("unable to construct new cert pool using cluster CA data"))
			})
		})

		When("client connection can be created with provided auth token", func() {
			It("should create the connection without error", func() {
				tempDir := GinkgoT().TempDir()
				caFilePath := filepath.Join(tempDir, "ca.crt")
				err := os.WriteFile(caFilePath, clusterCACertPEM, os.ModePerm)
				Expect(err).To(BeNil())

				lis := bufconn.Listen(1024)
				defer lis.Close()

				serviceClient, close, err := serviceClientFactory(logger, "token", &Config{
					ClusterCAFilePath: caFilePath,
					NextProto:         "nextProto",
					APIServerFQDN:     lis.Addr().String(),
				})

				Expect(err).To(BeNil())
				Expect(close).ToNot(BeNil())
				Expect(serviceClient).ToNot(BeNil())

				_ = close()
			})
		})
	})

	Context("getTLSConfig tests", func() {
		var rootPool *x509.CertPool

		BeforeEach(func() {
			rootPool = x509.NewCertPool()
			ok := rootPool.AppendCertsFromPEM(clusterCACertPEM)
			Expect(ok).To(BeTrue())
		})

		When("nextProto is not supplied", func() {
			It("should not include NextProtos in returned config", func() {
				config, err := getTLSConfig(clusterCACertPEM, "", false)
				Expect(err).To(BeNil())
				Expect(config).ToNot(BeNil())
				Expect(config.NextProtos).To(BeNil())
				Expect(config.InsecureSkipVerify).To(BeFalse())
				Expect(config.RootCAs.Equal(rootPool)).To(BeTrue())
			})
		})

		When("nextProto is supplied", func() {
			It("should include NextProtos in returned config", func() {
				config, err := getTLSConfig(clusterCACertPEM, "bootstrap", false)
				Expect(err).To(BeNil())
				Expect(config).NotTo(BeNil())
				Expect(config.NextProtos).NotTo(BeNil())
				Expect(config.NextProtos).To(Equal([]string{"bootstrap", "h2"}))
				Expect(config.InsecureSkipVerify).To(BeFalse())
				Expect(config.RootCAs.Equal(rootPool)).To(BeTrue())
			})
		})

		When("insecureSkipVerify is false", func() {
			It("should return config with false value of InsecureSkipVerify", func() {
				config, err := getTLSConfig(clusterCACertPEM, "nextProto", false)
				Expect(err).To(BeNil())
				Expect(config).NotTo(BeNil())
				Expect(config.InsecureSkipVerify).To(BeFalse())
				Expect(config.RootCAs.Equal(rootPool)).To(BeTrue())
			})
		})

		When("insecureSkipVerify is true", func() {
			It("should return config with true value of InsecureSkipVerify", func() {
				config, err := getTLSConfig(clusterCACertPEM, "nextProto", true)
				Expect(err).To(BeNil())
				Expect(config).NotTo(BeNil())
				Expect(config.InsecureSkipVerify).To(BeTrue())
				Expect(config.RootCAs.Equal(rootPool)).To(BeTrue())
			})
		})
	})
})
