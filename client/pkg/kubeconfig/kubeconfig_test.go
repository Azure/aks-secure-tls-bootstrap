// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package kubeconfig

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"time"

	"github.com/Azure/aks-secure-tls-bootstrap/client/pkg/testutil"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("kubeconfig tests", func() {
	Context("GenerateKubeconfigForCertAndKey", func() {
		It("should generate a valid kubeconfig containing the kubelet client credential", func() {
			tempDir := GinkgoT().TempDir()
			certPath := filepath.Join(tempDir, "client.crt")
			keyPath := filepath.Join(tempDir, "client.key")

			certPEM, keyPEM, err := testutil.GenerateCertPEMWithExpiration("system:node:node", "system:nodes", time.Now().Add(time.Hour))
			Expect(err).To(BeNil())
			block, rest := pem.Decode(keyPEM)
			Expect(rest).To(BeEmpty())
			privateKey, err := x509.ParseECPrivateKey(block.Bytes)
			Expect(err).To(BeNil())

			cfg := &GenerationConfig{
				APIServerFQDN:     "host",
				ClusterCAFilePath: "path",
				CertFilePath:      certPath,
				KeyFilePath:       keyPath,
			}

			kubeconfigData, err := GenerateForCertAndKey(certPEM, privateKey, cfg)
			Expect(err).To(BeNil())
			Expect(kubeconfigData.Clusters).To(HaveKey("default-cluster"))
			defaultCluster := kubeconfigData.Clusters["default-cluster"]
			Expect(defaultCluster.Server).To(Equal("https://host:443"))
			Expect(defaultCluster.CertificateAuthority).To(Equal(cfg.ClusterCAFilePath))

			Expect(kubeconfigData.AuthInfos).To(HaveKey("default-auth"))
			defaultAuth := kubeconfigData.AuthInfos["default-auth"]
			Expect(defaultAuth.ClientCertificate).To(Equal(certPath))
			Expect(defaultAuth.ClientKey).To(Equal(keyPath))

			Expect(kubeconfigData.Contexts).To(HaveKey("default-context"))
			defaultContext := kubeconfigData.Contexts["default-context"]
			Expect(defaultContext.Cluster).To(Equal("default-cluster"))
			Expect(defaultContext.AuthInfo).To(Equal("default-auth"))

			Expect(kubeconfigData.CurrentContext).To(Equal("default-context"))

			certData, err := os.ReadFile(certPath)
			Expect(err).To(BeNil())
			Expect(certData).ToNot(BeEmpty())

			keyData, err := os.ReadFile(keyPath)
			Expect(err).To(BeNil())
			Expect(keyData).ToNot(BeEmpty())
		})
	})
})
