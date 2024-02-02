// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package kubeconfig

import (
	"crypto/x509"
	"encoding/pem"
	"time"

	"github.com/Azure/aks-secure-tls-bootstrap/client/pkg/testutil"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("kubeconfig tests", func() {
	Context("GenerateKubeconfigForCertAndKey", func() {
		It("should generate a valid kubeconfig containing the kubelet client credential", func() {
			certPEM, keyPEM, err := testutil.GenerateCertPEMWithExpiration("system:node:node", "system:nodes", time.Now().Add(time.Hour))
			Expect(err).To(BeNil())
			block, rest := pem.Decode(keyPEM)
			Expect(rest).To(BeEmpty())
			privateKey, err := x509.ParseECPrivateKey(block.Bytes)
			Expect(err).To(BeNil())

			opts := &GenerateOpts{
				APIServerFQDN:     "host",
				ClusterCAFilePath: "path/to/ca.crt",
			}

			kubeconfigData, err := GenerateKubeconfigForCertAndKey(certPEM, privateKey, opts)
			Expect(err).To(BeNil())
			Expect(kubeconfigData.Clusters).To(HaveKey("default-cluster"))
			defaultCluster := kubeconfigData.Clusters["default-cluster"]
			Expect(defaultCluster.Server).To(Equal(opts.APIServerFQDN))
			Expect(defaultCluster.CertificateAuthority).To(Equal(opts.ClusterCAFilePath))

			Expect(kubeconfigData.AuthInfos).To(HaveKey("default-auth"))
			defaultAuth := kubeconfigData.AuthInfos["default-auth"]
			Expect(defaultAuth.ClientCertificateData).To(Equal(certPEM))
			Expect(defaultAuth.ClientKeyData).To(Equal(keyPEM))

			Expect(kubeconfigData.Contexts).To(HaveKey("default-context"))
			defaultContext := kubeconfigData.Contexts["default-context"]
			Expect(defaultContext.Cluster).To(Equal("default-cluster"))
			Expect(defaultContext.AuthInfo).To(Equal("default-auth"))

			Expect(kubeconfigData.CurrentContext).To(Equal("default-context"))
		})
	})
})
