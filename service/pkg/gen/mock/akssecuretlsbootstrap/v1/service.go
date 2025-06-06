// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Code generated by MockGen. DO NOT EDIT.
// Source: pkg/gen/akssecuretlsbootstrap/v1/service_grpc.pb.go
//
// Generated by this command:
//
//	mockgen -package=mocks -copyright_file=../hack/copyright_header.txt -source=pkg/gen/akssecuretlsbootstrap/v1/service_grpc.pb.go -destination=pkg/gen/mock/akssecuretlsbootstrap/v1/service.go
//

// Package mocks is a generated GoMock package.
package mocks

import (
	context "context"
	reflect "reflect"

	akssecuretlsbootstrapv1 "github.com/Azure/aks-secure-tls-bootstrap/service/pkg/gen/akssecuretlsbootstrap/v1"
	gomock "go.uber.org/mock/gomock"
	grpc "google.golang.org/grpc"
)

// MockSecureTLSBootstrapServiceClient is a mock of SecureTLSBootstrapServiceClient interface.
type MockSecureTLSBootstrapServiceClient struct {
	ctrl     *gomock.Controller
	recorder *MockSecureTLSBootstrapServiceClientMockRecorder
	isgomock struct{}
}

// MockSecureTLSBootstrapServiceClientMockRecorder is the mock recorder for MockSecureTLSBootstrapServiceClient.
type MockSecureTLSBootstrapServiceClientMockRecorder struct {
	mock *MockSecureTLSBootstrapServiceClient
}

// NewMockSecureTLSBootstrapServiceClient creates a new mock instance.
func NewMockSecureTLSBootstrapServiceClient(ctrl *gomock.Controller) *MockSecureTLSBootstrapServiceClient {
	mock := &MockSecureTLSBootstrapServiceClient{ctrl: ctrl}
	mock.recorder = &MockSecureTLSBootstrapServiceClientMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockSecureTLSBootstrapServiceClient) EXPECT() *MockSecureTLSBootstrapServiceClientMockRecorder {
	return m.recorder
}

// GetCredential mocks base method.
func (m *MockSecureTLSBootstrapServiceClient) GetCredential(ctx context.Context, in *akssecuretlsbootstrapv1.GetCredentialRequest, opts ...grpc.CallOption) (*akssecuretlsbootstrapv1.GetCredentialResponse, error) {
	m.ctrl.T.Helper()
	varargs := []any{ctx, in}
	for _, a := range opts {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "GetCredential", varargs...)
	ret0, _ := ret[0].(*akssecuretlsbootstrapv1.GetCredentialResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetCredential indicates an expected call of GetCredential.
func (mr *MockSecureTLSBootstrapServiceClientMockRecorder) GetCredential(ctx, in any, opts ...any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]any{ctx, in}, opts...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetCredential", reflect.TypeOf((*MockSecureTLSBootstrapServiceClient)(nil).GetCredential), varargs...)
}

// GetNonce mocks base method.
func (m *MockSecureTLSBootstrapServiceClient) GetNonce(ctx context.Context, in *akssecuretlsbootstrapv1.GetNonceRequest, opts ...grpc.CallOption) (*akssecuretlsbootstrapv1.GetNonceResponse, error) {
	m.ctrl.T.Helper()
	varargs := []any{ctx, in}
	for _, a := range opts {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "GetNonce", varargs...)
	ret0, _ := ret[0].(*akssecuretlsbootstrapv1.GetNonceResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetNonce indicates an expected call of GetNonce.
func (mr *MockSecureTLSBootstrapServiceClientMockRecorder) GetNonce(ctx, in any, opts ...any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]any{ctx, in}, opts...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetNonce", reflect.TypeOf((*MockSecureTLSBootstrapServiceClient)(nil).GetNonce), varargs...)
}

// MockSecureTLSBootstrapServiceServer is a mock of SecureTLSBootstrapServiceServer interface.
type MockSecureTLSBootstrapServiceServer struct {
	ctrl     *gomock.Controller
	recorder *MockSecureTLSBootstrapServiceServerMockRecorder
	isgomock struct{}
}

// MockSecureTLSBootstrapServiceServerMockRecorder is the mock recorder for MockSecureTLSBootstrapServiceServer.
type MockSecureTLSBootstrapServiceServerMockRecorder struct {
	mock *MockSecureTLSBootstrapServiceServer
}

// NewMockSecureTLSBootstrapServiceServer creates a new mock instance.
func NewMockSecureTLSBootstrapServiceServer(ctrl *gomock.Controller) *MockSecureTLSBootstrapServiceServer {
	mock := &MockSecureTLSBootstrapServiceServer{ctrl: ctrl}
	mock.recorder = &MockSecureTLSBootstrapServiceServerMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockSecureTLSBootstrapServiceServer) EXPECT() *MockSecureTLSBootstrapServiceServerMockRecorder {
	return m.recorder
}

// GetCredential mocks base method.
func (m *MockSecureTLSBootstrapServiceServer) GetCredential(arg0 context.Context, arg1 *akssecuretlsbootstrapv1.GetCredentialRequest) (*akssecuretlsbootstrapv1.GetCredentialResponse, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetCredential", arg0, arg1)
	ret0, _ := ret[0].(*akssecuretlsbootstrapv1.GetCredentialResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetCredential indicates an expected call of GetCredential.
func (mr *MockSecureTLSBootstrapServiceServerMockRecorder) GetCredential(arg0, arg1 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetCredential", reflect.TypeOf((*MockSecureTLSBootstrapServiceServer)(nil).GetCredential), arg0, arg1)
}

// GetNonce mocks base method.
func (m *MockSecureTLSBootstrapServiceServer) GetNonce(arg0 context.Context, arg1 *akssecuretlsbootstrapv1.GetNonceRequest) (*akssecuretlsbootstrapv1.GetNonceResponse, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetNonce", arg0, arg1)
	ret0, _ := ret[0].(*akssecuretlsbootstrapv1.GetNonceResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetNonce indicates an expected call of GetNonce.
func (mr *MockSecureTLSBootstrapServiceServerMockRecorder) GetNonce(arg0, arg1 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetNonce", reflect.TypeOf((*MockSecureTLSBootstrapServiceServer)(nil).GetNonce), arg0, arg1)
}

// mustEmbedUnimplementedSecureTLSBootstrapServiceServer mocks base method.
func (m *MockSecureTLSBootstrapServiceServer) mustEmbedUnimplementedSecureTLSBootstrapServiceServer() {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "mustEmbedUnimplementedSecureTLSBootstrapServiceServer")
}

// mustEmbedUnimplementedSecureTLSBootstrapServiceServer indicates an expected call of mustEmbedUnimplementedSecureTLSBootstrapServiceServer.
func (mr *MockSecureTLSBootstrapServiceServerMockRecorder) mustEmbedUnimplementedSecureTLSBootstrapServiceServer() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "mustEmbedUnimplementedSecureTLSBootstrapServiceServer", reflect.TypeOf((*MockSecureTLSBootstrapServiceServer)(nil).mustEmbedUnimplementedSecureTLSBootstrapServiceServer))
}

// MockUnsafeSecureTLSBootstrapServiceServer is a mock of UnsafeSecureTLSBootstrapServiceServer interface.
type MockUnsafeSecureTLSBootstrapServiceServer struct {
	ctrl     *gomock.Controller
	recorder *MockUnsafeSecureTLSBootstrapServiceServerMockRecorder
	isgomock struct{}
}

// MockUnsafeSecureTLSBootstrapServiceServerMockRecorder is the mock recorder for MockUnsafeSecureTLSBootstrapServiceServer.
type MockUnsafeSecureTLSBootstrapServiceServerMockRecorder struct {
	mock *MockUnsafeSecureTLSBootstrapServiceServer
}

// NewMockUnsafeSecureTLSBootstrapServiceServer creates a new mock instance.
func NewMockUnsafeSecureTLSBootstrapServiceServer(ctrl *gomock.Controller) *MockUnsafeSecureTLSBootstrapServiceServer {
	mock := &MockUnsafeSecureTLSBootstrapServiceServer{ctrl: ctrl}
	mock.recorder = &MockUnsafeSecureTLSBootstrapServiceServerMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockUnsafeSecureTLSBootstrapServiceServer) EXPECT() *MockUnsafeSecureTLSBootstrapServiceServerMockRecorder {
	return m.recorder
}

// mustEmbedUnimplementedSecureTLSBootstrapServiceServer mocks base method.
func (m *MockUnsafeSecureTLSBootstrapServiceServer) mustEmbedUnimplementedSecureTLSBootstrapServiceServer() {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "mustEmbedUnimplementedSecureTLSBootstrapServiceServer")
}

// mustEmbedUnimplementedSecureTLSBootstrapServiceServer indicates an expected call of mustEmbedUnimplementedSecureTLSBootstrapServiceServer.
func (mr *MockUnsafeSecureTLSBootstrapServiceServerMockRecorder) mustEmbedUnimplementedSecureTLSBootstrapServiceServer() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "mustEmbedUnimplementedSecureTLSBootstrapServiceServer", reflect.TypeOf((*MockUnsafeSecureTLSBootstrapServiceServer)(nil).mustEmbedUnimplementedSecureTLSBootstrapServiceServer))
}
