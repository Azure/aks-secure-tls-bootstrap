// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/Azure/aks-secure-tls-bootstrap/pkg/client (interfaces: ImdsClient)

// Package mocks is a generated GoMock package.
package mocks

import (
	context "context"
	reflect "reflect"

	datamodel "github.com/Azure/aks-secure-tls-bootstrap/client/pkg/datamodel"
	gomock "go.uber.org/mock/gomock"
)

// MockImdsClient is a mock of ImdsClient interface.
type MockImdsClient struct {
	ctrl     *gomock.Controller
	recorder *MockImdsClientMockRecorder
}

// MockImdsClientMockRecorder is the mock recorder for MockImdsClient.
type MockImdsClientMockRecorder struct {
	mock *MockImdsClient
}

// NewMockImdsClient creates a new mock instance.
func NewMockImdsClient(ctrl *gomock.Controller) *MockImdsClient {
	mock := &MockImdsClient{ctrl: ctrl}
	mock.recorder = &MockImdsClientMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockImdsClient) EXPECT() *MockImdsClientMockRecorder {
	return m.recorder
}

// GetAttestedData mocks base method.
func (m *MockImdsClient) GetAttestedData(arg0 context.Context, arg1, arg2 string) (*datamodel.VMSSAttestedData, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetAttestedData", arg0, arg1, arg2)
	ret0, _ := ret[0].(*datamodel.VMSSAttestedData)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetAttestedData indicates an expected call of GetAttestedData.
func (mr *MockImdsClientMockRecorder) GetAttestedData(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetAttestedData", reflect.TypeOf((*MockImdsClient)(nil).GetAttestedData), arg0, arg1, arg2)
}

// GetInstanceData mocks base method.
func (m *MockImdsClient) GetInstanceData(arg0 context.Context, arg1 string) (*datamodel.VMSSInstanceData, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetInstanceData", arg0, arg1)
	ret0, _ := ret[0].(*datamodel.VMSSInstanceData)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetInstanceData indicates an expected call of GetInstanceData.
func (mr *MockImdsClientMockRecorder) GetInstanceData(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetInstanceData", reflect.TypeOf((*MockImdsClient)(nil).GetInstanceData), arg0, arg1)
}

// GetMSIToken mocks base method.
func (m *MockImdsClient) GetMSIToken(arg0 context.Context, arg1, arg2, arg3 string) (*datamodel.AADTokenResponse, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetMSIToken", arg0, arg1, arg2, arg3)
	ret0, _ := ret[0].(*datamodel.AADTokenResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetMSIToken indicates an expected call of GetMSIToken.
func (mr *MockImdsClientMockRecorder) GetMSIToken(arg0, arg1, arg2, arg3 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetMSIToken", reflect.TypeOf((*MockImdsClient)(nil).GetMSIToken), arg0, arg1, arg2, arg3)
}
