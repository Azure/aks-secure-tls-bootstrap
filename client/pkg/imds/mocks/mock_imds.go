// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/Azure/aks-secure-tls-bootstrap/client/pkg/imds (interfaces: Client)

// Package mocks is a generated GoMock package.
package mocks

import (
	context "context"
	reflect "reflect"

	datamodel "github.com/Azure/aks-secure-tls-bootstrap/client/pkg/datamodel"
	gomock "go.uber.org/mock/gomock"
)

// MockClient is a mock of Client interface.
type MockClient struct {
	ctrl     *gomock.Controller
	recorder *MockClientMockRecorder
}

// MockClientMockRecorder is the mock recorder for MockClient.
type MockClientMockRecorder struct {
	mock *MockClient
}

// NewMockClient creates a new mock instance.
func NewMockClient(ctrl *gomock.Controller) *MockClient {
	mock := &MockClient{ctrl: ctrl}
	mock.recorder = &MockClientMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockClient) EXPECT() *MockClientMockRecorder {
	return m.recorder
}

// GetAttestedData mocks base method.
func (m *MockClient) GetAttestedData(arg0 context.Context, arg1 string) (*datamodel.VMSSAttestedData, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetAttestedData", arg0, arg1)
	ret0, _ := ret[0].(*datamodel.VMSSAttestedData)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetAttestedData indicates an expected call of GetAttestedData.
func (mr *MockClientMockRecorder) GetAttestedData(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetAttestedData", reflect.TypeOf((*MockClient)(nil).GetAttestedData), arg0, arg1)
}

// GetInstanceData mocks base method.
func (m *MockClient) GetInstanceData(arg0 context.Context) (*datamodel.VMSSInstanceData, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetInstanceData", arg0)
	ret0, _ := ret[0].(*datamodel.VMSSInstanceData)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetInstanceData indicates an expected call of GetInstanceData.
func (mr *MockClientMockRecorder) GetInstanceData(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetInstanceData", reflect.TypeOf((*MockClient)(nil).GetInstanceData), arg0)
}

// GetMSIToken mocks base method.
func (m *MockClient) GetMSIToken(arg0 context.Context, arg1, arg2 string) (string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetMSIToken", arg0, arg1, arg2)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetMSIToken indicates an expected call of GetMSIToken.
func (mr *MockClientMockRecorder) GetMSIToken(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetMSIToken", reflect.TypeOf((*MockClient)(nil).GetMSIToken), arg0, arg1, arg2)
}
