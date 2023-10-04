// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package client

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

const (
	mockMSITokenResponseJSON = `{"access_token":"accesstoken","refresh_token":"refreshtoken"}`
	mockVMSSInstanceDataJSON = `{"compute":{"resourceId": "resourceId"}}`
	mockVMSSAttestedDataJSON = `{"signature":"signature"}`
)

func mockImdsWithAssertions(response string, assertions func(r *http.Request)) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assertions(r)
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, response)
	}))
}

var _ = Describe("TLS Bootstrap Client IMDS tests", func() {
	var (
		imdsClient = NewImdsClient(testLogger)
	)

	Context("getImdsData tests", func() {
		It("should specify Metadata:True in the request headers", func() {
			imds := mockImdsWithAssertions("{}", func(r *http.Request) {
				Expect(r.Header.Get("Metadata")).To(Equal("True"))
			})
			defer imds.Close()

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			err := getImdsData(ctx, testLogger, imds.URL, map[string]string{}, &struct{}{})
			Expect(err).To(BeNil())
		})

		When("there aren't query parameters", func() {
			It("should not add query parameters to to the request URL", func() {
				imds := mockImdsWithAssertions("{}", func(r *http.Request) {
					Expect(r.URL.Query()).To(BeEmpty())
				})
				defer imds.Close()

				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()

				err := getImdsData(ctx, testLogger, imds.URL, map[string]string{}, &struct{}{})
				Expect(err).To(BeNil())
			})
		})

		When("there are query parameters", func() {
			It("should add the the query parameters to the request URL", func() {
				params := map[string]string{
					"a": "1",
					"b": "2",
					"c": "3",
				}
				imds := mockImdsWithAssertions("{}", func(r *http.Request) {
					queryParameters := r.URL.Query()
					for param, expectedValue := range params {
						Expect(queryParameters.Get(param)).To(Equal(expectedValue))
					}
				})
				defer imds.Close()

				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()

				err := getImdsData(ctx, testLogger, imds.URL, params, &struct{}{})
				Expect(err).To(BeNil())
			})
		})
	})

	Context("GetMSIToken tests", func() {
		When("clientId is not included", func() {
			It("should call the correct IMDS endpoint with the correct query parameters", func() {
				imds := mockImdsWithAssertions(mockMSITokenResponseJSON, func(r *http.Request) {
					Expect(r.URL.Path).To(Equal("/metadata/identity/oauth2/token"))
					queryParameters := r.URL.Query()
					Expect(queryParameters.Get("api-version")).To(Equal("2018-02-01"))
					Expect(queryParameters.Get("resource")).To(Equal(defaultAKSAADServerAppID))
					Expect(queryParameters.Has("client_id")).To(BeFalse())
				})
				defer imds.Close()

				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()

				tokenResp, err := imdsClient.GetMSIToken(ctx, imds.URL, "")
				Expect(err).To(BeNil())
				Expect(tokenResp).NotTo(BeNil())
				Expect(tokenResp.AccessToken).To(Equal("accesstoken"))
				Expect(tokenResp.RefreshToken).To(Equal("refreshtoken"))
			})
		})

		When("clientId is included", func() {
			It("should call the correct IMDS endpoint with the correct query parameters", func() {
				imds := mockImdsWithAssertions(mockMSITokenResponseJSON, func(r *http.Request) {
					Expect(r.URL.Path).To(Equal("/metadata/identity/oauth2/token"))
					queryParameters := r.URL.Query()
					Expect(queryParameters.Get("api-version")).To(Equal("2018-02-01"))
					Expect(queryParameters.Get("resource")).To(Equal(defaultAKSAADServerAppID))
					Expect(queryParameters.Get("client_id")).To(Equal("clientId"))
				})
				defer imds.Close()

				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()

				clientID := "clientId"
				tokenResp, err := imdsClient.GetMSIToken(ctx, imds.URL, clientID)
				Expect(err).To(BeNil())
				Expect(tokenResp).NotTo(BeNil())
				Expect(tokenResp.AccessToken).To(Equal("accesstoken"))
				Expect(tokenResp.RefreshToken).To(Equal("refreshtoken"))
			})
		})
	})

	Context("GetInstanceData tests", func() {
		It("should call the correct IMDS endpoint with the correct query parameters", func() {
			imds := mockImdsWithAssertions(mockVMSSInstanceDataJSON, func(r *http.Request) {
				Expect(r.URL.Path).To(Equal("/metadata/instance"))
				queryParameters := r.URL.Query()
				Expect(queryParameters.Get("api-version")).To(Equal("2021-05-01"))
				Expect(queryParameters.Get("format")).To(Equal("json"))
			})
			defer imds.Close()

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			instanceData, err := imdsClient.GetInstanceData(ctx, imds.URL)
			Expect(err).To(BeNil())
			Expect(instanceData).ToNot(BeNil())
			Expect(instanceData.Compute.ResourceID).To(Equal("resourceId"))
		})
	})

	Context("GetAttestedData tests", func() {
		It("should call the correct IMDS endpoint with the correct query parameters", func() {
			imds := mockImdsWithAssertions(mockVMSSAttestedDataJSON, func(r *http.Request) {
				Expect(r.URL.Path).To(Equal("/metadata/attested/document"))
				queryParameters := r.URL.Query()
				Expect(queryParameters.Get("api-version")).To(Equal("2021-05-01"))
				Expect(queryParameters.Get("format")).To(Equal("json"))
				Expect(queryParameters.Get("nonce")).To(Equal("nonce"))
			})
			defer imds.Close()

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			nonce := "nonce"
			attestedData, err := imdsClient.GetAttestedData(ctx, imds.URL, nonce)
			Expect(err).To(BeNil())
			Expect(attestedData).ToNot(BeNil())
			Expect(attestedData.Signature).To(Equal("signature"))
		})
	})
})
