// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Code generated by MockGen. DO NOT EDIT.
// Source: protos/bootstrap_grpc.pb.go

// Package mocks is a generated GoMock package.
package mocks

import (
	context "context"
	reflect "reflect"

	protos "github.com/Azure/aks-secure-tls-bootstrap/service/protos"
	gomock "go.uber.org/mock/gomock"
	grpc "google.golang.org/grpc"
)

// MockSecureTLSBootstrapServiceClient is a mock of SecureTLSBootstrapServiceClient interface.
type MockSecureTLSBootstrapServiceClient struct {
	ctrl     *gomock.Controller
	recorder *MockSecureTLSBootstrapServiceClientMockRecorder
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
func (m *MockSecureTLSBootstrapServiceClient) GetCredential(ctx context.Context, in *protos.CredentialRequest, opts ...grpc.CallOption) (*protos.CredentialResponse, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{ctx, in}
	for _, a := range opts {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "GetCredential", varargs...)
	ret0, _ := ret[0].(*protos.CredentialResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetCredential indicates an expected call of GetCredential.
func (mr *MockSecureTLSBootstrapServiceClientMockRecorder) GetCredential(ctx, in interface{}, opts ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{ctx, in}, opts...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetCredential", reflect.TypeOf((*MockSecureTLSBootstrapServiceClient)(nil).GetCredential), varargs...)
}

// GetNonce mocks base method.
func (m *MockSecureTLSBootstrapServiceClient) GetNonce(ctx context.Context, in *protos.NonceRequest, opts ...grpc.CallOption) (*protos.NonceResponse, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{ctx, in}
	for _, a := range opts {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "GetNonce", varargs...)
	ret0, _ := ret[0].(*protos.NonceResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetNonce indicates an expected call of GetNonce.
func (mr *MockSecureTLSBootstrapServiceClientMockRecorder) GetNonce(ctx, in interface{}, opts ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{ctx, in}, opts...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetNonce", reflect.TypeOf((*MockSecureTLSBootstrapServiceClient)(nil).GetNonce), varargs...)
}

// GetToken mocks base method.
func (m *MockSecureTLSBootstrapServiceClient) GetToken(ctx context.Context, in *protos.TokenRequest, opts ...grpc.CallOption) (*protos.TokenResponse, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{ctx, in}
	for _, a := range opts {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "GetToken", varargs...)
	ret0, _ := ret[0].(*protos.TokenResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetToken indicates an expected call of GetToken.
func (mr *MockSecureTLSBootstrapServiceClientMockRecorder) GetToken(ctx, in interface{}, opts ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{ctx, in}, opts...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetToken", reflect.TypeOf((*MockSecureTLSBootstrapServiceClient)(nil).GetToken), varargs...)
}

// MockSecureTLSBootstrapServiceServer is a mock of SecureTLSBootstrapServiceServer interface.
type MockSecureTLSBootstrapServiceServer struct {
	ctrl     *gomock.Controller
	recorder *MockSecureTLSBootstrapServiceServerMockRecorder
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
func (m *MockSecureTLSBootstrapServiceServer) GetCredential(arg0 context.Context, arg1 *protos.CredentialRequest) (*protos.CredentialResponse, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetCredential", arg0, arg1)
	ret0, _ := ret[0].(*protos.CredentialResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetCredential indicates an expected call of GetCredential.
func (mr *MockSecureTLSBootstrapServiceServerMockRecorder) GetCredential(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetCredential", reflect.TypeOf((*MockSecureTLSBootstrapServiceServer)(nil).GetCredential), arg0, arg1)
}

// GetNonce mocks base method.
func (m *MockSecureTLSBootstrapServiceServer) GetNonce(arg0 context.Context, arg1 *protos.NonceRequest) (*protos.NonceResponse, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetNonce", arg0, arg1)
	ret0, _ := ret[0].(*protos.NonceResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetNonce indicates an expected call of GetNonce.
func (mr *MockSecureTLSBootstrapServiceServerMockRecorder) GetNonce(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetNonce", reflect.TypeOf((*MockSecureTLSBootstrapServiceServer)(nil).GetNonce), arg0, arg1)
}

// GetToken mocks base method.
func (m *MockSecureTLSBootstrapServiceServer) GetToken(arg0 context.Context, arg1 *protos.TokenRequest) (*protos.TokenResponse, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetToken", arg0, arg1)
	ret0, _ := ret[0].(*protos.TokenResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetToken indicates an expected call of GetToken.
func (mr *MockSecureTLSBootstrapServiceServerMockRecorder) GetToken(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetToken", reflect.TypeOf((*MockSecureTLSBootstrapServiceServer)(nil).GetToken), arg0, arg1)
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
