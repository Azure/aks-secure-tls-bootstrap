// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package imds

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"

	internalhttp "github.com/Azure/aks-secure-tls-bootstrap/client/internal/http"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"go.uber.org/zap"
)

var _ = Describe("Client Tests", Ordered, func() {
	const (
		mockVMInstanceDataJSON = `{"compute":{"resourceId": "resourceId"}}`
		mockVMAttestedDataJSON = `{"signature":"signature"}`
		malformedJSON          = `{{}`
	)
	var (
		logger     *zap.Logger
		imdsClient *client
	)

	BeforeAll(func() {
		logger, _ = zap.NewDevelopment()
	})

	BeforeEach(func() {
		imdsClient = &client{
			httpClient: internalhttp.NewClient(logger),
			logger:     logger,
		}
	})

	Context("callIMDS", func() {
		It("should specify Metadata:True in the request headers", func() {
			imds := mockIMDSWithAssertions("{}", func(r *http.Request) {
				Expect(r.Header.Get("Metadata")).To(Equal("True"))
			})
			defer imds.Close()

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			err := imdsClient.callIMDS(ctx, imds.URL, map[string]string{}, &VMInstanceData{})
			Expect(err).To(BeNil())
		})

		When("there aren't query parameters", func() {
			It("should not add query parameters to to the request URL", func() {
				imds := mockIMDSWithAssertions("{}", func(r *http.Request) {
					Expect(r.URL.Query()).To(BeEmpty())
				})
				defer imds.Close()

				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()

				err := imdsClient.callIMDS(ctx, imds.URL, map[string]string{}, &VMInstanceData{})
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
				imds := mockIMDSWithAssertions("{}", func(r *http.Request) {
					queryParameters := r.URL.Query()
					for param, expectedValue := range params {
						Expect(queryParameters.Get(param)).To(Equal(expectedValue))
					}
				})
				defer imds.Close()

				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()

				err := imdsClient.callIMDS(ctx, imds.URL, params, &VMInstanceData{})
				Expect(err).To(BeNil())
			})
		})
	})

	Context("GetInstanceData tests", func() {
		It("should call the correct IMDS endpoint with the correct query parameters", func() {
			imds := mockIMDSWithAssertions(mockVMInstanceDataJSON, func(r *http.Request) {
				Expect(r.URL.Path).To(Equal("/metadata/instance"))
				queryParameters := r.URL.Query()
				Expect(queryParameters.Get("api-version")).To(Equal(apiVersion))
				Expect(queryParameters.Get("format")).To(Equal("json"))
			})
			defer imds.Close()
			imdsClient.baseURL = imds.URL

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			instanceData, err := imdsClient.GetInstanceData(ctx)
			Expect(err).To(BeNil())
			Expect(instanceData).ToNot(BeNil())
			Expect(instanceData.Compute.ResourceID).To(Equal("resourceId"))
		})

		When("unable parse instance data response from IMDS", func() {
			It("should return an error", func() {
				imds := mockIMDSWithAssertions(malformedJSON, func(r *http.Request) {
					Expect(r.URL.Path).To(Equal("/metadata/instance"))
					queryParameters := r.URL.Query()
					Expect(queryParameters.Get("api-version")).To(Equal(apiVersion))
					Expect(queryParameters.Get("format")).To(Equal("json"))
				})
				defer imds.Close()
				imdsClient.baseURL = imds.URL

				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()

				instanceData, err := imdsClient.GetInstanceData(ctx)
				Expect(instanceData).To(BeNil())
				Expect(err).ToNot(BeNil())
				Expect(err.Error()).To(ContainSubstring("failed to unmarshal IMDS data"))
			})
		})
	})

	Context("GetAttestedData tests", func() {
		It("should call the correct IMDS endpoint with the correct query parameters", func() {
			imds := mockIMDSWithAssertions(mockVMAttestedDataJSON, func(r *http.Request) {
				Expect(r.URL.Path).To(Equal("/metadata/attested/document"))
				queryParameters := r.URL.Query()
				Expect(queryParameters.Get("api-version")).To(Equal(apiVersion))
				Expect(queryParameters.Get("format")).To(Equal("json"))
				Expect(queryParameters.Get("nonce")).To(Equal("nonce"))
			})
			defer imds.Close()
			imdsClient.baseURL = imds.URL

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			nonce := "nonce"
			attestedData, err := imdsClient.GetAttestedData(ctx, nonce)
			Expect(err).To(BeNil())
			Expect(attestedData).ToNot(BeNil())
			Expect(attestedData.Signature).To(Equal("signature"))
		})

		When("unable to parse instance data response from IMDS", func() {
			It("should return an error", func() {
				imds := mockIMDSWithAssertions(malformedJSON, func(r *http.Request) {
					Expect(r.URL.Path).To(Equal("/metadata/attested/document"))
					queryParameters := r.URL.Query()
					Expect(queryParameters.Get("api-version")).To(Equal(apiVersion))
					Expect(queryParameters.Get("format")).To(Equal("json"))
					Expect(queryParameters.Get("nonce")).To(Equal("nonce"))
				})
				defer imds.Close()
				imdsClient.baseURL = imds.URL

				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()

				nonce := "nonce"
				attestedData, err := imdsClient.GetAttestedData(ctx, nonce)
				Expect(attestedData).To(BeNil())
				Expect(err).ToNot(BeNil())
				Expect(err.Error()).To(ContainSubstring("failed to unmarshal IMDS data"))
			})
		})
	})
})

func mockIMDSWithAssertions(response string, assertions func(r *http.Request)) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		Expect(r.Header.Get("User-Agent")).To(HavePrefix("aks-secure-tls-bootstrap-client/"))
		assertions(r)
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, response)
	}))
}
