// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/Azure/aks-tls-bootstrap-client/pkg/client (interfaces: AadClient)

// Package mocks is a generated GoMock package.
package mocks

import (
	context "context"
	reflect "reflect"

	datamodel "github.com/Azure/aks-tls-bootstrap-client/client/pkg/datamodel"
	gomock "go.uber.org/mock/gomock"
)

// MockAadClient is a mock of AadClient interface.
type MockAadClient struct {
	ctrl     *gomock.Controller
	recorder *MockAadClientMockRecorder
}

// MockAadClientMockRecorder is the mock recorder for MockAadClient.
type MockAadClientMockRecorder struct {
	mock *MockAadClient
}

// NewMockAadClient creates a new mock instance.
func NewMockAadClient(ctrl *gomock.Controller) *MockAadClient {
	mock := &MockAadClient{ctrl: ctrl}
	mock.recorder = &MockAadClientMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockAadClient) EXPECT() *MockAadClientMockRecorder {
	return m.recorder
}

// GetAadToken mocks base method.
func (m *MockAadClient) GetAadToken(arg0 context.Context, arg1 *datamodel.AzureConfig, arg2 string) (string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetAadToken", arg0, arg1, arg2)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetAadToken indicates an expected call of GetAadToken.
func (mr *MockAadClientMockRecorder) GetAadToken(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetAadToken", reflect.TypeOf((*MockAadClient)(nil).GetAadToken), arg0, arg1, arg2)
}
