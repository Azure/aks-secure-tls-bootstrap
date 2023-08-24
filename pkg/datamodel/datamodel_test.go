package datamodel

import (
	"time"

	"github.com/golang-jwt/jwt/v4"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("datamodel tests", func() {
	Context("AzureADTokenClaims validation tests", func() {
		When("appid is empty", func() {
			It("should invalidate the claims", func() {
				claims := &AzureADTokenClaims{
					Tid: "tid",
					RegisteredClaims: jwt.RegisteredClaims{
						ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
					},
				}
				err := claims.Valid()
				Expect(err).ToNot(BeNil())
				Expect(err.Error()).To(ContainSubstring("appid claim must be included and non-empty"))
			})
		})

		When("tid is empty", func() {
			It("shoudl invalidate the claims", func() {
				claims := &AzureADTokenClaims{
					AppID: "appid",
					RegisteredClaims: jwt.RegisteredClaims{
						ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
					},
				}
				err := claims.Valid()
				Expect(err).ToNot(BeNil())
				Expect(err.Error()).To(ContainSubstring("tid claim must be included and non-empty"))
			})
		})

		When("claims are expired", func() {
			It("should invalidate the claims", func() {
				claims := &AzureADTokenClaims{
					AppID: "appid",
					Tid:   "tid",
					RegisteredClaims: jwt.RegisteredClaims{
						ExpiresAt: jwt.NewNumericDate(time.Now()),
					},
				}
				err := claims.Valid()
				Expect(err).ToNot(BeNil())
				Expect(err.Error()).To(ContainSubstring("token is expired"))
			})
		})

		When("claims are valid", func() {
			It("should successfully validate the claims", func() {
				claims := &AzureADTokenClaims{
					AppID: "appid",
					Tid:   "tid",
					RegisteredClaims: jwt.RegisteredClaims{
						ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
					},
				}
				err := claims.Valid()
				Expect(err).To(BeNil())
			})
		})
	})
})
