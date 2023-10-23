package client

import (
	"context"
	"fmt"

	"github.com/Azure/aks-tls-bootstrap-client/pkg/client/mocks"
	base "github.com/AzureAD/microsoft-authentication-library-for-go/apps/confidential"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"go.uber.org/mock/gomock"
)

var _ = Describe("Aad tests", func() {
	var (
		mockCtrl     *gomock.Controller
		AadClient    = NewAadClient(testLogger)
		mockAcquirer *mocks.MockTokenAcquirer
	)

	BeforeEach(func() {
		mockCtrl = gomock.NewController(GinkgoT())
		mockAcquirer = mocks.NewMockTokenAcquirer(mockCtrl)
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
		When("newAadTokenAcquirer returns a valid tokenAcquierer", func() {
			It("should return the mocked token", func() {
				dummyAuth := base.AuthResult{AccessToken: "dummyAuth"}
				mockAcquirer.EXPECT().Acquire(gomock.Any(), gomock.Any()).Return(dummyAuth, nil).Times(1)
				newTokenAcquirer = func(authority, clientID, clientSecret string) (TokenAcquirer, error) {
					return mockAcquirer, nil
				}

				originalImpl := newAadTokenAcquirer
				defer func() {
					newTokenAcquirer = originalImpl
				}()

				token, err := AadClient.GetAadToken(context.Background(), gomock.Any().String(), gomock.Any().String(), gomock.Any().String(), gomock.Any().String())
				Expect(token).To(Equal(dummyAuth.AccessToken))
				Expect(err).To(BeNil())
			})
		})
	})

	Context("Test GetAadToken", func() {
		When("newAadTokenAcquirer returns an error", func() {
			It("should return an error", func() {
				dummyAuth := base.AuthResult{}
				mockAcquirer.EXPECT().Acquire(gomock.Any(), gomock.Any()).Return(dummyAuth, fmt.Errorf("error")).AnyTimes()
				newTokenAcquirer = func(authority, clientID, clientSecret string) (TokenAcquirer, error) {
					return mockAcquirer, nil
				}

				originalImpl := newAadTokenAcquirer
				defer func() {
					newTokenAcquirer = originalImpl
				}()

				token, err := AadClient.GetAadToken(context.Background(), gomock.Any().String(), gomock.Any().String(), gomock.Any().String(), gomock.Any().String())
				Expect(token).To(Equal(""))
				Expect(err).ToNot(BeNil())
			})
		})
	})
})
