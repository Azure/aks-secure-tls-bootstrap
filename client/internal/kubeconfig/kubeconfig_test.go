// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package kubeconfig

import (
	"encoding/pem"
	"os"
	"path/filepath"
	"time"

	"github.com/Azure/aks-secure-tls-bootstrap/client/internal/testutil"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("kubeconfig tests", func() {
	Context("GenerateKubeconfigForCertAndKey", func() {
		It("should generate a valid kubeconfig containing the kubelet client credential", func() {
			tempDir := GinkgoT().TempDir()
			credPath := filepath.Join(tempDir, "client.pem")

			certPEM, keyPEM, err := testutil.GenerateCertPEM(testutil.CertTemplate{
				CommonName:   "system:node:node",
				Organization: "system:nodes",
				Expiration:   time.Now().Add(time.Hour),
			})
			Expect(err).To(BeNil())

			cfg := &Config{
				APIServerFQDN:     "host",
				ClusterCAFilePath: "path",
				CredFilePath:      credPath,
			}

			kubeconfigData, err := GenerateForCertAndKey(certPEM, keyPEM, cfg)
			Expect(err).To(BeNil())
			Expect(kubeconfigData.Clusters).To(HaveKey("default-cluster"))
			defaultCluster := kubeconfigData.Clusters["default-cluster"]
			Expect(defaultCluster.Server).To(Equal("https://host:443"))
			Expect(defaultCluster.CertificateAuthority).To(Equal(cfg.ClusterCAFilePath))

			Expect(kubeconfigData.AuthInfos).To(HaveKey("default-auth"))
			defaultAuth := kubeconfigData.AuthInfos["default-auth"]
			Expect(defaultAuth.ClientCertificate).To(Equal(credPath))
			Expect(defaultAuth.ClientKey).To(Equal(credPath))

			Expect(kubeconfigData.Contexts).To(HaveKey("default-context"))
			defaultContext := kubeconfigData.Contexts["default-context"]
			Expect(defaultContext.Cluster).To(Equal("default-cluster"))
			Expect(defaultContext.AuthInfo).To(Equal("default-auth"))

			Expect(kubeconfigData.CurrentContext).To(Equal("default-context"))

			credData, err := os.ReadFile(credPath)
			Expect(err).To(BeNil())
			Expect(credData).ToNot(BeNil())

			certBlock, rest := pem.Decode(credData)
			Expect(certBlock).ToNot(BeNil())
			Expect(certBlock.Type).To(Equal("CERTIFICATE"))
			Expect(rest).ToNot(BeEmpty())

			keyBlock, rest := pem.Decode(rest)
			Expect(keyBlock).ToNot(BeNil())
			Expect(keyBlock.Type).To(Equal("EC PRIVATE KEY"))
			Expect(rest).To(BeEmpty())
		})
	})
})
