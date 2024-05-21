// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package bootstrap

import (
	"context"
	"crypto/x509"
	"os"
	"path/filepath"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"google.golang.org/grpc/test/bufconn"

	"github.com/Azure/aks-secure-tls-bootstrap/client/pkg/testutil"
)

var _ = Describe("grpc", func() {
	const (
		nextProto = "nextProto"
	)
	clusterCACertPEM, _, err := testutil.GenerateCertPEMWithExpiration("hcp", "aks", time.Now().Add(time.Hour))
	Expect(err).To(BeNil())

	Context("secureTLSBootstrapServiceClientFactory", func() {
		When("cluster ca data cannot be read", func() {
			It("should return an error", func() {
				caFilePath := "does/not/exist.crt"

				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()

				serviceClient, conn, err := secureTLSBootstrapServiceClientFactory(ctx, testLogger, &serviceClientFactoryConfig{
					clusterCAFilePath: caFilePath,
					nextProto:         nextProto,
					authToken:         "token",
					fqdn:              "fqdn",
				})
				Expect(serviceClient).To(BeNil())
				Expect(conn).To(BeNil())
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

				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()

				serviceClient, conn, err := secureTLSBootstrapServiceClientFactory(ctx, testLogger, &serviceClientFactoryConfig{
					clusterCAFilePath: caFilePath,
					nextProto:         nextProto,
					authToken:         "token",
					fqdn:              "fqdn",
				})
				Expect(serviceClient).To(BeNil())
				Expect(conn).To(BeNil())
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

				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				lis := bufconn.Listen(1024)
				defer lis.Close()
				fqdn := lis.Addr().String()

				serviceClient, conn, err := secureTLSBootstrapServiceClientFactory(ctx, testLogger, &serviceClientFactoryConfig{
					clusterCAFilePath: caFilePath,
					nextProto:         nextProto,
					authToken:         "token",
					fqdn:              fqdn,
				})
				defer conn.Close()

				Expect(err).To(BeNil())
				Expect(conn).ToNot(BeNil())
				Expect(serviceClient).ToNot(BeNil())
			})
		})
	})

	Context("getTLSConfig tests", func() {
		var poolWithCACert *x509.CertPool

		BeforeEach(func() {
			poolWithCACert = x509.NewCertPool()
			ok := poolWithCACert.AppendCertsFromPEM(clusterCACertPEM)
			Expect(ok).To(BeTrue())
		})

		When("nextProto is not supplied", func() {
			It("should not include NextProtos in returned config", func() {
				config, err := getTLSConfig(clusterCACertPEM, "", false)
				Expect(err).To(BeNil())
				Expect(config).ToNot(BeNil())
				Expect(config.NextProtos).To(BeNil())
				Expect(config.InsecureSkipVerify).To(BeFalse())
				Expect(config.RootCAs.Equal(poolWithCACert)).To(BeTrue())
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
				Expect(config.RootCAs.Equal(poolWithCACert)).To(BeTrue())
			})
		})

		When("insecureSkipVerify is false", func() {
			It("should return config with false value of InsecureSkipVerify", func() {
				config, err := getTLSConfig(clusterCACertPEM, "nextProto", false)
				Expect(err).To(BeNil())
				Expect(config).NotTo(BeNil())
				Expect(config.InsecureSkipVerify).To(BeFalse())
				Expect(config.RootCAs.Equal(poolWithCACert)).To(BeTrue())
			})
		})

		When("insecureSkipVerify is true", func() {
			It("should return config with true value of InsecureSkipVerify", func() {
				config, err := getTLSConfig(clusterCACertPEM, "nextProto", true)
				Expect(err).To(BeNil())
				Expect(config).NotTo(BeNil())
				Expect(config.InsecureSkipVerify).To(BeTrue())
				Expect(config.RootCAs.Equal(poolWithCACert)).To(BeTrue())
			})
		})
	})
})
