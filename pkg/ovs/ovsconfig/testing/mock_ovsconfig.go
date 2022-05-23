// Copyright 2022 Antrea Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

// Code generated by MockGen. DO NOT EDIT.
// Source: antrea.io/antrea/pkg/ovs/ovsconfig (interfaces: OVSBridgeClient)

// Package testing is a generated GoMock package.
package testing

import (
	ovsconfig "antrea.io/antrea/pkg/ovs/ovsconfig"
	gomock "github.com/golang/mock/gomock"
	reflect "reflect"
)

// MockOVSBridgeClient is a mock of OVSBridgeClient interface
type MockOVSBridgeClient struct {
	ctrl     *gomock.Controller
	recorder *MockOVSBridgeClientMockRecorder
}

// MockOVSBridgeClientMockRecorder is the mock recorder for MockOVSBridgeClient
type MockOVSBridgeClientMockRecorder struct {
	mock *MockOVSBridgeClient
}

// NewMockOVSBridgeClient creates a new mock instance
func NewMockOVSBridgeClient(ctrl *gomock.Controller) *MockOVSBridgeClient {
	mock := &MockOVSBridgeClient{ctrl: ctrl}
	mock.recorder = &MockOVSBridgeClientMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *MockOVSBridgeClient) EXPECT() *MockOVSBridgeClientMockRecorder {
	return m.recorder
}

// AddBridgeOtherConfig mocks base method
func (m *MockOVSBridgeClient) AddBridgeOtherConfig(arg0 map[string]interface{}) ovsconfig.Error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "AddBridgeOtherConfig", arg0)
	ret0, _ := ret[0].(ovsconfig.Error)
	return ret0
}

// AddBridgeOtherConfig indicates an expected call of AddBridgeOtherConfig
func (mr *MockOVSBridgeClientMockRecorder) AddBridgeOtherConfig(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AddBridgeOtherConfig", reflect.TypeOf((*MockOVSBridgeClient)(nil).AddBridgeOtherConfig), arg0)
}

// AddOVSOtherConfig mocks base method
func (m *MockOVSBridgeClient) AddOVSOtherConfig(arg0 map[string]interface{}) ovsconfig.Error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "AddOVSOtherConfig", arg0)
	ret0, _ := ret[0].(ovsconfig.Error)
	return ret0
}

// AddOVSOtherConfig indicates an expected call of AddOVSOtherConfig
func (mr *MockOVSBridgeClientMockRecorder) AddOVSOtherConfig(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AddOVSOtherConfig", reflect.TypeOf((*MockOVSBridgeClient)(nil).AddOVSOtherConfig), arg0)
}

// Create mocks base method
func (m *MockOVSBridgeClient) Create() ovsconfig.Error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Create")
	ret0, _ := ret[0].(ovsconfig.Error)
	return ret0
}

// Create indicates an expected call of Create
func (mr *MockOVSBridgeClientMockRecorder) Create() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Create", reflect.TypeOf((*MockOVSBridgeClient)(nil).Create))
}

// CreateAccessPort mocks base method
func (m *MockOVSBridgeClient) CreateAccessPort(arg0, arg1 string, arg2 map[string]interface{}, arg3 uint16) (string, ovsconfig.Error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CreateAccessPort", arg0, arg1, arg2, arg3)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(ovsconfig.Error)
	return ret0, ret1
}

// CreateAccessPort indicates an expected call of CreateAccessPort
func (mr *MockOVSBridgeClientMockRecorder) CreateAccessPort(arg0, arg1, arg2, arg3 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreateAccessPort", reflect.TypeOf((*MockOVSBridgeClient)(nil).CreateAccessPort), arg0, arg1, arg2, arg3)
}

// CreateInternalPort mocks base method
func (m *MockOVSBridgeClient) CreateInternalPort(arg0 string, arg1 int32, arg2 map[string]interface{}) (string, ovsconfig.Error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CreateInternalPort", arg0, arg1, arg2)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(ovsconfig.Error)
	return ret0, ret1
}

// CreateInternalPort indicates an expected call of CreateInternalPort
func (mr *MockOVSBridgeClientMockRecorder) CreateInternalPort(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreateInternalPort", reflect.TypeOf((*MockOVSBridgeClient)(nil).CreateInternalPort), arg0, arg1, arg2)
}

// CreatePort mocks base method
func (m *MockOVSBridgeClient) CreatePort(arg0, arg1 string, arg2 map[string]interface{}) (string, ovsconfig.Error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CreatePort", arg0, arg1, arg2)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(ovsconfig.Error)
	return ret0, ret1
}

// CreatePort indicates an expected call of CreatePort
func (mr *MockOVSBridgeClientMockRecorder) CreatePort(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreatePort", reflect.TypeOf((*MockOVSBridgeClient)(nil).CreatePort), arg0, arg1, arg2)
}

// CreateTunnelPort mocks base method
func (m *MockOVSBridgeClient) CreateTunnelPort(arg0 string, arg1 ovsconfig.TunnelType, arg2 int32) (string, ovsconfig.Error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CreateTunnelPort", arg0, arg1, arg2)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(ovsconfig.Error)
	return ret0, ret1
}

// CreateTunnelPort indicates an expected call of CreateTunnelPort
func (mr *MockOVSBridgeClientMockRecorder) CreateTunnelPort(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreateTunnelPort", reflect.TypeOf((*MockOVSBridgeClient)(nil).CreateTunnelPort), arg0, arg1, arg2)
}

// CreateTunnelPortExt mocks base method
func (m *MockOVSBridgeClient) CreateTunnelPortExt(arg0 string, arg1 ovsconfig.TunnelType, arg2 int32, arg3 bool, arg4, arg5, arg6, arg7 string, arg8, arg9 map[string]interface{}) (string, ovsconfig.Error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CreateTunnelPortExt", arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(ovsconfig.Error)
	return ret0, ret1
}

// CreateTunnelPortExt indicates an expected call of CreateTunnelPortExt
func (mr *MockOVSBridgeClientMockRecorder) CreateTunnelPortExt(arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreateTunnelPortExt", reflect.TypeOf((*MockOVSBridgeClient)(nil).CreateTunnelPortExt), arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9)
}

// CreateUplinkPort mocks base method
func (m *MockOVSBridgeClient) CreateUplinkPort(arg0 string, arg1 int32, arg2 map[string]interface{}) (string, ovsconfig.Error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CreateUplinkPort", arg0, arg1, arg2)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(ovsconfig.Error)
	return ret0, ret1
}

// CreateUplinkPort indicates an expected call of CreateUplinkPort
func (mr *MockOVSBridgeClientMockRecorder) CreateUplinkPort(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreateUplinkPort", reflect.TypeOf((*MockOVSBridgeClient)(nil).CreateUplinkPort), arg0, arg1, arg2)
}

// Delete mocks base method
func (m *MockOVSBridgeClient) Delete() ovsconfig.Error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Delete")
	ret0, _ := ret[0].(ovsconfig.Error)
	return ret0
}

// Delete indicates an expected call of Delete
func (mr *MockOVSBridgeClientMockRecorder) Delete() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Delete", reflect.TypeOf((*MockOVSBridgeClient)(nil).Delete))
}

// DeleteOVSOtherConfig mocks base method
func (m *MockOVSBridgeClient) DeleteOVSOtherConfig(arg0 map[string]interface{}) ovsconfig.Error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DeleteOVSOtherConfig", arg0)
	ret0, _ := ret[0].(ovsconfig.Error)
	return ret0
}

// DeleteOVSOtherConfig indicates an expected call of DeleteOVSOtherConfig
func (mr *MockOVSBridgeClientMockRecorder) DeleteOVSOtherConfig(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DeleteOVSOtherConfig", reflect.TypeOf((*MockOVSBridgeClient)(nil).DeleteOVSOtherConfig), arg0)
}

// DeletePort mocks base method
func (m *MockOVSBridgeClient) DeletePort(arg0 string) ovsconfig.Error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DeletePort", arg0)
	ret0, _ := ret[0].(ovsconfig.Error)
	return ret0
}

// DeletePort indicates an expected call of DeletePort
func (mr *MockOVSBridgeClientMockRecorder) DeletePort(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DeletePort", reflect.TypeOf((*MockOVSBridgeClient)(nil).DeletePort), arg0)
}

// DeletePorts mocks base method
func (m *MockOVSBridgeClient) DeletePorts(arg0 []string) ovsconfig.Error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DeletePorts", arg0)
	ret0, _ := ret[0].(ovsconfig.Error)
	return ret0
}

// DeletePorts indicates an expected call of DeletePorts
func (mr *MockOVSBridgeClientMockRecorder) DeletePorts(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DeletePorts", reflect.TypeOf((*MockOVSBridgeClient)(nil).DeletePorts), arg0)
}

// GetBridgeName mocks base method
func (m *MockOVSBridgeClient) GetBridgeName() string {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetBridgeName")
	ret0, _ := ret[0].(string)
	return ret0
}

// GetBridgeName indicates an expected call of GetBridgeName
func (mr *MockOVSBridgeClientMockRecorder) GetBridgeName() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetBridgeName", reflect.TypeOf((*MockOVSBridgeClient)(nil).GetBridgeName))
}

// GetExternalIDs mocks base method
func (m *MockOVSBridgeClient) GetExternalIDs() (map[string]string, ovsconfig.Error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetExternalIDs")
	ret0, _ := ret[0].(map[string]string)
	ret1, _ := ret[1].(ovsconfig.Error)
	return ret0, ret1
}

// GetExternalIDs indicates an expected call of GetExternalIDs
func (mr *MockOVSBridgeClientMockRecorder) GetExternalIDs() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetExternalIDs", reflect.TypeOf((*MockOVSBridgeClient)(nil).GetExternalIDs))
}

// GetInterfaceOptions mocks base method
func (m *MockOVSBridgeClient) GetInterfaceOptions(arg0 string) (map[string]string, ovsconfig.Error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetInterfaceOptions", arg0)
	ret0, _ := ret[0].(map[string]string)
	ret1, _ := ret[1].(ovsconfig.Error)
	return ret0, ret1
}

// GetInterfaceOptions indicates an expected call of GetInterfaceOptions
func (mr *MockOVSBridgeClientMockRecorder) GetInterfaceOptions(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetInterfaceOptions", reflect.TypeOf((*MockOVSBridgeClient)(nil).GetInterfaceOptions), arg0)
}

// GetOFPort mocks base method
func (m *MockOVSBridgeClient) GetOFPort(arg0 string, arg1 bool) (int32, ovsconfig.Error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetOFPort", arg0, arg1)
	ret0, _ := ret[0].(int32)
	ret1, _ := ret[1].(ovsconfig.Error)
	return ret0, ret1
}

// GetOFPort indicates an expected call of GetOFPort
func (mr *MockOVSBridgeClientMockRecorder) GetOFPort(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetOFPort", reflect.TypeOf((*MockOVSBridgeClient)(nil).GetOFPort), arg0, arg1)
}

// GetOVSDatapathType mocks base method
func (m *MockOVSBridgeClient) GetOVSDatapathType() ovsconfig.OVSDatapathType {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetOVSDatapathType")
	ret0, _ := ret[0].(ovsconfig.OVSDatapathType)
	return ret0
}

// GetOVSDatapathType indicates an expected call of GetOVSDatapathType
func (mr *MockOVSBridgeClientMockRecorder) GetOVSDatapathType() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetOVSDatapathType", reflect.TypeOf((*MockOVSBridgeClient)(nil).GetOVSDatapathType))
}

// GetOVSOtherConfig mocks base method
func (m *MockOVSBridgeClient) GetOVSOtherConfig() (map[string]string, ovsconfig.Error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetOVSOtherConfig")
	ret0, _ := ret[0].(map[string]string)
	ret1, _ := ret[1].(ovsconfig.Error)
	return ret0, ret1
}

// GetOVSOtherConfig indicates an expected call of GetOVSOtherConfig
func (mr *MockOVSBridgeClientMockRecorder) GetOVSOtherConfig() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetOVSOtherConfig", reflect.TypeOf((*MockOVSBridgeClient)(nil).GetOVSOtherConfig))
}

// GetOVSVersion mocks base method
func (m *MockOVSBridgeClient) GetOVSVersion() (string, ovsconfig.Error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetOVSVersion")
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(ovsconfig.Error)
	return ret0, ret1
}

// GetOVSVersion indicates an expected call of GetOVSVersion
func (mr *MockOVSBridgeClientMockRecorder) GetOVSVersion() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetOVSVersion", reflect.TypeOf((*MockOVSBridgeClient)(nil).GetOVSVersion))
}

// GetPortData mocks base method
func (m *MockOVSBridgeClient) GetPortData(arg0, arg1 string) (*ovsconfig.OVSPortData, ovsconfig.Error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetPortData", arg0, arg1)
	ret0, _ := ret[0].(*ovsconfig.OVSPortData)
	ret1, _ := ret[1].(ovsconfig.Error)
	return ret0, ret1
}

// GetPortData indicates an expected call of GetPortData
func (mr *MockOVSBridgeClientMockRecorder) GetPortData(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetPortData", reflect.TypeOf((*MockOVSBridgeClient)(nil).GetPortData), arg0, arg1)
}

// GetPortList mocks base method
func (m *MockOVSBridgeClient) GetPortList() ([]ovsconfig.OVSPortData, ovsconfig.Error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetPortList")
	ret0, _ := ret[0].([]ovsconfig.OVSPortData)
	ret1, _ := ret[1].(ovsconfig.Error)
	return ret0, ret1
}

// GetPortList indicates an expected call of GetPortList
func (mr *MockOVSBridgeClientMockRecorder) GetPortList() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetPortList", reflect.TypeOf((*MockOVSBridgeClient)(nil).GetPortList))
}

// IsHardwareOffloadEnabled mocks base method
func (m *MockOVSBridgeClient) IsHardwareOffloadEnabled() bool {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "IsHardwareOffloadEnabled")
	ret0, _ := ret[0].(bool)
	return ret0
}

// IsHardwareOffloadEnabled indicates an expected call of IsHardwareOffloadEnabled
func (mr *MockOVSBridgeClientMockRecorder) IsHardwareOffloadEnabled() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "IsHardwareOffloadEnabled", reflect.TypeOf((*MockOVSBridgeClient)(nil).IsHardwareOffloadEnabled))
}

// SetBridgeMcastSnooping mocks base method
func (m *MockOVSBridgeClient) SetBridgeMcastSnooping(arg0 bool) ovsconfig.Error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SetBridgeMcastSnooping", arg0)
	ret0, _ := ret[0].(ovsconfig.Error)
	return ret0
}

// SetBridgeMcastSnooping indicates an expected call of SetBridgeMcastSnooping
func (mr *MockOVSBridgeClientMockRecorder) SetBridgeMcastSnooping(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SetBridgeMcastSnooping", reflect.TypeOf((*MockOVSBridgeClient)(nil).SetBridgeMcastSnooping), arg0)
}

// SetDatapathID mocks base method
func (m *MockOVSBridgeClient) SetDatapathID(arg0 string) ovsconfig.Error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SetDatapathID", arg0)
	ret0, _ := ret[0].(ovsconfig.Error)
	return ret0
}

// SetDatapathID indicates an expected call of SetDatapathID
func (mr *MockOVSBridgeClientMockRecorder) SetDatapathID(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SetDatapathID", reflect.TypeOf((*MockOVSBridgeClient)(nil).SetDatapathID), arg0)
}

// SetExternalIDs mocks base method
func (m *MockOVSBridgeClient) SetExternalIDs(arg0 map[string]interface{}) ovsconfig.Error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SetExternalIDs", arg0)
	ret0, _ := ret[0].(ovsconfig.Error)
	return ret0
}

// SetExternalIDs indicates an expected call of SetExternalIDs
func (mr *MockOVSBridgeClientMockRecorder) SetExternalIDs(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SetExternalIDs", reflect.TypeOf((*MockOVSBridgeClient)(nil).SetExternalIDs), arg0)
}

// SetInterfaceMTU mocks base method
func (m *MockOVSBridgeClient) SetInterfaceMTU(arg0 string, arg1 int) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SetInterfaceMTU", arg0, arg1)
	ret0, _ := ret[0].(error)
	return ret0
}

// SetInterfaceMTU indicates an expected call of SetInterfaceMTU
func (mr *MockOVSBridgeClientMockRecorder) SetInterfaceMTU(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SetInterfaceMTU", reflect.TypeOf((*MockOVSBridgeClient)(nil).SetInterfaceMTU), arg0, arg1)
}

// SetInterfaceOptions mocks base method
func (m *MockOVSBridgeClient) SetInterfaceOptions(arg0 string, arg1 map[string]interface{}) ovsconfig.Error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SetInterfaceOptions", arg0, arg1)
	ret0, _ := ret[0].(ovsconfig.Error)
	return ret0
}

// SetInterfaceOptions indicates an expected call of SetInterfaceOptions
func (mr *MockOVSBridgeClientMockRecorder) SetInterfaceOptions(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SetInterfaceOptions", reflect.TypeOf((*MockOVSBridgeClient)(nil).SetInterfaceOptions), arg0, arg1)
}

// SetInterfaceType mocks base method
func (m *MockOVSBridgeClient) SetInterfaceType(arg0, arg1 string) ovsconfig.Error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SetInterfaceType", arg0, arg1)
	ret0, _ := ret[0].(ovsconfig.Error)
	return ret0
}

// SetInterfaceType indicates an expected call of SetInterfaceType
func (mr *MockOVSBridgeClientMockRecorder) SetInterfaceType(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SetInterfaceType", reflect.TypeOf((*MockOVSBridgeClient)(nil).SetInterfaceType), arg0, arg1)
}

// SetPortExternalIDs mocks base method
func (m *MockOVSBridgeClient) SetPortExternalIDs(arg0 string, arg1 map[string]interface{}) ovsconfig.Error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SetPortExternalIDs", arg0, arg1)
	ret0, _ := ret[0].(ovsconfig.Error)
	return ret0
}

// SetPortExternalIDs indicates an expected call of SetPortExternalIDs
func (mr *MockOVSBridgeClientMockRecorder) SetPortExternalIDs(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SetPortExternalIDs", reflect.TypeOf((*MockOVSBridgeClient)(nil).SetPortExternalIDs), arg0, arg1)
}
