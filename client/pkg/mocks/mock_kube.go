// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Code generated by MockGen. DO NOT EDIT.
// Source: kubeconfig.go

// Package mocks is a generated GoMock package.
package mocks

import (
	reflect "reflect"

	gomock "go.uber.org/mock/gomock"
)

// MockKubeClient is a mock of KubeClient interface.
type MockKubeClient struct {
	ctrl     *gomock.Controller
	recorder *MockKubeClientMockRecorder
}

// MockKubeClientMockRecorder is the mock recorder for MockKubeClient.
type MockKubeClientMockRecorder struct {
	mock *MockKubeClient
}

// NewMockKubeClient creates a new mock instance.
func NewMockKubeClient(ctrl *gomock.Controller) *MockKubeClient {
	mock := &MockKubeClient{ctrl: ctrl}
	mock.recorder = &MockKubeClientMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockKubeClient) EXPECT() *MockKubeClientMockRecorder {
	return m.recorder
}

// EnsureClusterConnectivity mocks base method.
func (m *MockKubeClient) EnsureClusterConnectivity(kubeConfigPath string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "EnsureClusterConnectivity", kubeConfigPath)
	ret0, _ := ret[0].(error)
	return ret0
}

// EnsureClusterConnectivity indicates an expected call of EnsureClusterConnectivity.
func (mr *MockKubeClientMockRecorder) EnsureClusterConnectivity(kubeConfigPath interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "EnsureClusterConnectivity", reflect.TypeOf((*MockKubeClient)(nil).EnsureClusterConnectivity), kubeConfigPath)
}

// IsKubeConfigStillValid mocks base method.
func (m *MockKubeClient) IsKubeConfigStillValid(kubeConfigPath string) (bool, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "IsKubeConfigStillValid", kubeConfigPath)
	ret0, _ := ret[0].(bool)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// IsKubeConfigStillValid indicates an expected call of IsKubeConfigStillValid.
func (mr *MockKubeClientMockRecorder) IsKubeConfigStillValid(kubeConfigPath interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "IsKubeConfigStillValid", reflect.TypeOf((*MockKubeClient)(nil).IsKubeConfigStillValid), kubeConfigPath)
}