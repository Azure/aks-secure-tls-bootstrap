package client

import (
	"context"

	"github.com/Azure/aks-tls-bootstrap-client/pkg/client/mocks"
	base "github.com/AzureAD/microsoft-authentication-library-for-go/apps/confidential"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"go.uber.org/mock/gomock"
)

var _ = Describe("Aad tests", func() {
	var (
		mockCtrl           *gomock.Controller
		tokenInterfaceMock *mocks.MockGetTokenInterface
		AadClient          = NewAadClient(testLogger)
	)

	BeforeEach(func() {
		mockCtrl = gomock.NewController(GinkgoT())
		tokenInterfaceMock = mocks.NewMockGetTokenInterface(mockCtrl)
	})

	AfterEach(func() {
		mockCtrl.Finish()
	})

	Context("Test NewAadClient", func() {
		It("should return a new AadClient", func() {
			Expect(AadClient).ToNot(BeNil())
		})
	})

	Context("Test GetAadToken", func() {
		It("should return AadToken", func() {
			dummyAuth := base.AuthResult{AccessToken: "dummyAuth"}
			tokenInterfaceMock.EXPECT().
				GetTokenWithClient(gomock.Any(), gomock.Any(), gomock.Any()).
				Return(dummyAuth.AccessToken, nil).
				Times(1)

			originalImpl := getTokenImplGlobalController
			getTokenImplGlobalController = tokenInterfaceMock
			defer func() {
				getTokenImplGlobalController = originalImpl // Restore the original implementation.
			}()

			_, cancel := context.WithCancel(context.Background())
			defer cancel()

			token, err := AadClient.GetAadToken(context.Background(), gomock.Any().String(), gomock.Any().String(), gomock.Any().String(), gomock.Any().String())
			Expect(token).To(Equal(dummyAuth.AccessToken))
			Expect(err).To(BeNil())
		})
	})
})
