// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/Azure/aks-tls-bootstrap-client/pkg/protos (interfaces: AKSBootstrapTokenRequestClient)

// Package mocks is a generated GoMock package.
package mocks

import (
	context "context"
	reflect "reflect"

	protos "github.com/Azure/aks-tls-bootstrap-client/pkg/protos"
	gomock "go.uber.org/mock/gomock"
	grpc "google.golang.org/grpc"
)

// MockAKSBootstrapTokenRequestClient is a mock of AKSBootstrapTokenRequestClient interface.
type MockAKSBootstrapTokenRequestClient struct {
	ctrl     *gomock.Controller
	recorder *MockAKSBootstrapTokenRequestClientMockRecorder
}

// MockAKSBootstrapTokenRequestClientMockRecorder is the mock recorder for MockAKSBootstrapTokenRequestClient.
type MockAKSBootstrapTokenRequestClientMockRecorder struct {
	mock *MockAKSBootstrapTokenRequestClient
}

// NewMockAKSBootstrapTokenRequestClient creates a new mock instance.
func NewMockAKSBootstrapTokenRequestClient(ctrl *gomock.Controller) *MockAKSBootstrapTokenRequestClient {
	mock := &MockAKSBootstrapTokenRequestClient{ctrl: ctrl}
	mock.recorder = &MockAKSBootstrapTokenRequestClientMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockAKSBootstrapTokenRequestClient) EXPECT() *MockAKSBootstrapTokenRequestClientMockRecorder {
	return m.recorder
}

// GetNonce mocks base method.
func (m *MockAKSBootstrapTokenRequestClient) GetNonce(arg0 context.Context, arg1 *protos.NonceRequest, arg2 ...grpc.CallOption) (*protos.NonceResponse, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{arg0, arg1}
	for _, a := range arg2 {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "GetNonce", varargs...)
	ret0, _ := ret[0].(*protos.NonceResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetNonce indicates an expected call of GetNonce.
func (mr *MockAKSBootstrapTokenRequestClientMockRecorder) GetNonce(arg0, arg1 interface{}, arg2 ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{arg0, arg1}, arg2...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetNonce", reflect.TypeOf((*MockAKSBootstrapTokenRequestClient)(nil).GetNonce), varargs...)
}

// GetCredential mocks base method.
func (m *MockAKSBootstrapTokenRequestClient) GetCredential(arg0 context.Context, arg1 *protos.CredentialRequest, arg2 ...grpc.CallOption) (*protos.CredentialResponse, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{arg0, arg1}
	for _, a := range arg2 {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "GetCredential", varargs...)
	ret0, _ := ret[0].(*protos.CredentialResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetCredential indicates an expected call of GetCredential.
func (mr *MockAKSBootstrapTokenRequestClientMockRecorder) GetCredential(arg0, arg1 interface{}, arg2 ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{arg0, arg1}, arg2...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetCredential", reflect.TypeOf((*MockAKSBootstrapTokenRequestClient)(nil).GetCredential), varargs...)
}

// SetGRPCConnection mocks base method.
func (m *MockAKSBootstrapTokenRequestClient) SetGRPCConnection(arg0 *grpc.ClientConn) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "SetGRPCConnection", arg0)
}

// SetGRPCConnection indicates an expected call of SetGRPCConnection.
func (mr *MockAKSBootstrapTokenRequestClientMockRecorder) SetGRPCConnection(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SetGRPCConnection", reflect.TypeOf((*MockAKSBootstrapTokenRequestClient)(nil).SetGRPCConnection), arg0)
}
