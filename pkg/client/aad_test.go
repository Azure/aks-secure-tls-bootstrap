package client

import (
	"context"
	"errors"
	"fmt"

	"github.com/Azure/aks-tls-bootstrap-client/pkg/client/mocks"
	base "github.com/AzureAD/microsoft-authentication-library-for-go/apps/confidential"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"go.uber.org/mock/gomock"
)

var _ = Describe("Aad tests", func() {
	var (
		mockCtrl         *gomock.Controller
		mockAcquirer     *mocks.MockTokenAcquirer
		newTokenAcquirer func(authority, clientID, clientSecret string) (TokenAcquirer, error)
	)

	BeforeEach(func() {
		mockCtrl = gomock.NewController(GinkgoT())
		mockAcquirer = mocks.NewMockTokenAcquirer(mockCtrl)
	})

	AfterEach(func() {
		mockCtrl.Finish()
		newTokenAcquirer = newAadTokenAcquirer
	})

	Context("Test NewAadClient", func() {
		It("should return a new AadClient", func() {
			aadClient := NewAadClient(testLogger, newAadTokenAcquirer)
			Expect(aadClient).ToNot(BeNil())
		})
	})

	Context("Test GetAadToken", func() {
		When("tokenAcquirerFunc returns a valid tokenAcquierer", func() {
			It("should return the mocked token", func() {
				dummyAuth := base.AuthResult{AccessToken: "dummyAuth"}
				mockAcquirer.EXPECT().Acquire(gomock.Any(), gomock.Any()).Return(dummyAuth, nil).Times(1)
				newTokenAcquirer = func(authority, clientID, clientSecret string) (TokenAcquirer, error) {
					return mockAcquirer, nil
				}

				aadClient := NewAadClient(testLogger, newTokenAcquirer)

				token, err := aadClient.GetAadToken(context.Background(), gomock.Any().String(), gomock.Any().String(), gomock.Any().String(), gomock.Any().String())
				Expect(token).To(Equal(dummyAuth.AccessToken))
				Expect(err).To(BeNil())
			})
		})

		When("tokenAcquirerFunc returns an error", func() {
			It("should return an error", func() {
				dummyAuth := base.AuthResult{}
				mockAcquirer.EXPECT().Acquire(gomock.Any(), gomock.Any()).Return(dummyAuth, fmt.Errorf("error")).AnyTimes()
				newTokenAcquirer = func(authority, clientID, clientSecret string) (TokenAcquirer, error) {
					return mockAcquirer, nil
				}

				aadClient := NewAadClient(testLogger, newTokenAcquirer)

				token, err := aadClient.GetAadToken(context.Background(), gomock.Any().String(), gomock.Any().String(), gomock.Any().String(), gomock.Any().String())
				Expect(token).To(Equal(""))
				Expect(err).ToNot(BeNil())
				Expect(err.Error()).To(ContainSubstring("failed to acquire token via service principal"))
			})
		})

		When("Aquire returns an error", func() {
			It("should return an error", func() {
				dummyAuth := base.AuthResult{}
				mockAcquirer.EXPECT().Acquire(gomock.Any(), gomock.Any()).Return(dummyAuth, nil).AnyTimes()
				newTokenAcquirer = func(authority, clientID, clientSecret string) (TokenAcquirer, error) {
					return mockAcquirer, errors.New("error")
				}

				aadClient := NewAadClient(testLogger, newTokenAcquirer)
				token, err := aadClient.GetAadToken(context.Background(), gomock.Any().String(), gomock.Any().String(), gomock.Any().String(), gomock.Any().String())

				Expect(token).To(Equal(""))
				Expect(err).ToNot(BeNil())
				Expect(err.Error()).To(ContainSubstring("unable to construct new AAD token"))
			})
		})
	})

	Context("Test newAadTokenAcquirer", func() {
		It("should return a new tokenAcquirer", func() {
			tokenAcquirer, err := newAadTokenAcquirer("https://login.microsoft.com/dummy", "clientID", "clientSecret")
			Expect(tokenAcquirer).ToNot(BeNil())
			Expect(err).To(BeNil())
		})

		When("authority string is not a valid URL", func() {
			It("should return an error", func() {
				tokenAcquirer, err := newAadTokenAcquirer("invalid", "clientID", "clientSecret")
				Expect(err).ToNot(BeNil())
				Expect(err.Error()).To(ContainSubstring("failed to create client"))
				Expect(tokenAcquirer).To(BeNil())
			})
		})

		When("secret is an empty string", func() {
			It("should return an error", func() {
				tokenAcquirer, err := newAadTokenAcquirer("invalid", "clientID", "")
				Expect(err).ToNot(BeNil())
				Expect(err.Error()).To(ContainSubstring("secret can't be empty string"))
				Expect(tokenAcquirer).To(BeNil())
			})
		})
	})
})
