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
		mockCtrl              *gomock.Controller
		tokenInterfaceMock    *mocks.MockGetTokenInterface
		aquireTokenClientMock *mocks.MockAcquireTokenClient
		AadClient             = NewAadClient(testLogger)
		TokenController       = NewTokenWithClientInterface()
	)

	BeforeEach(func() {
		mockCtrl = gomock.NewController(GinkgoT())
		tokenInterfaceMock = mocks.NewMockGetTokenInterface(mockCtrl)
		aquireTokenClientMock = mocks.NewMockAcquireTokenClient(mockCtrl)
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
		When("When GetTokenWithClient is mocked", func() {
			It("should return the mocked token", func() {
				dummyAuth := base.AuthResult{AccessToken: "dummyAuth"}
				tokenInterfaceMock.EXPECT().
					GetTokenWithConfidentialClient(gomock.Any(), gomock.Any()).
					Return(dummyAuth.AccessToken, nil).
					Times(1)

				originalImpl := getTokenWithConfidentialClientImplFunc
				getTokenWithConfidentialClientImplFunc = tokenInterfaceMock
				defer func() {
					getTokenWithConfidentialClientImplFunc = originalImpl // Restore the original implementation.
				}()

				_, cancel := context.WithCancel(context.Background())
				defer cancel()

				token, err := AadClient.GetAadToken(context.Background(), gomock.Any().String(), gomock.Any().String(), gomock.Any().String(), gomock.Any().String())
				Expect(token).To(Equal(dummyAuth.AccessToken))
				Expect(err).To(BeNil())
			})
		})
	})

	Context("Test GetAadToken", func() {
		When("AcquireTokenByCredential is mocked", func() {
			It("Shoudl return the mocked authToken", func() {
				dummyAuth := base.AuthResult{AccessToken: "dummyAuth"}
				aquireTokenClientMock.EXPECT().AcquireTokenByCredential(gomock.Any(), gomock.Any()).Return(dummyAuth, nil).Times(1)
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()

				originalImpl := aquireTokenClient
				aquireTokenClient = aquireTokenClientMock
				defer func() {
					aquireTokenClient = originalImpl // Restore the original implementation.
				}()

				scopes := []string{"apple", "banana", "cherry"}
				accessToken, err := TokenController.GetTokenWithConfidentialClient(ctx, scopes)
				Expect(accessToken).To(Equal(dummyAuth.AccessToken))
				Expect(err).To(BeNil())
			})
		})
	})
})
