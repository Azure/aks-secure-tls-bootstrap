// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.36.5
// 	protoc        (unknown)
// source: akssecuretlsbootstrap/v1/credential.proto

package akssecuretlsbootstrapv1

import (
	_ "buf.build/gen/go/service-hub/loggable/protocolbuffers/go/proto"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
	unsafe "unsafe"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type GetCredentialRequest struct {
	state protoimpl.MessageState `protogen:"open.v1"`
	// Resource ID of the bootstrapping VM.
	ResourceId string `protobuf:"bytes,1,opt,name=resource_id,json=resourceId,proto3" json:"resource_id,omitempty"`
	// Nonce received from the GetNonce RPC.
	Nonce string `protobuf:"bytes,2,opt,name=nonce,proto3" json:"nonce,omitempty"`
	// Attested data blob retrieved from IMDS.
	AttestedData string `protobuf:"bytes,3,opt,name=attested_data,json=attestedData,proto3" json:"attested_data,omitempty"`
	// TLS CSR PEM, b64-encoded.
	EncodedCsrPem string `protobuf:"bytes,4,opt,name=encoded_csr_pem,json=encodedCsrPem,proto3" json:"encoded_csr_pem,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *GetCredentialRequest) Reset() {
	*x = GetCredentialRequest{}
	mi := &file_akssecuretlsbootstrap_v1_credential_proto_msgTypes[0]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *GetCredentialRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetCredentialRequest) ProtoMessage() {}

func (x *GetCredentialRequest) ProtoReflect() protoreflect.Message {
	mi := &file_akssecuretlsbootstrap_v1_credential_proto_msgTypes[0]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetCredentialRequest.ProtoReflect.Descriptor instead.
func (*GetCredentialRequest) Descriptor() ([]byte, []int) {
	return file_akssecuretlsbootstrap_v1_credential_proto_rawDescGZIP(), []int{0}
}

func (x *GetCredentialRequest) GetResourceId() string {
	if x != nil {
		return x.ResourceId
	}
	return ""
}

func (x *GetCredentialRequest) GetNonce() string {
	if x != nil {
		return x.Nonce
	}
	return ""
}

func (x *GetCredentialRequest) GetAttestedData() string {
	if x != nil {
		return x.AttestedData
	}
	return ""
}

func (x *GetCredentialRequest) GetEncodedCsrPem() string {
	if x != nil {
		return x.EncodedCsrPem
	}
	return ""
}

type GetCredentialResponse struct {
	state protoimpl.MessageState `protogen:"open.v1"`
	// Kubelet client certificate PEM, b64-encoded.
	EncodedCertPem string `protobuf:"bytes,1,opt,name=encoded_cert_pem,json=encodedCertPem,proto3" json:"encoded_cert_pem,omitempty"`
	unknownFields  protoimpl.UnknownFields
	sizeCache      protoimpl.SizeCache
}

func (x *GetCredentialResponse) Reset() {
	*x = GetCredentialResponse{}
	mi := &file_akssecuretlsbootstrap_v1_credential_proto_msgTypes[1]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *GetCredentialResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetCredentialResponse) ProtoMessage() {}

func (x *GetCredentialResponse) ProtoReflect() protoreflect.Message {
	mi := &file_akssecuretlsbootstrap_v1_credential_proto_msgTypes[1]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetCredentialResponse.ProtoReflect.Descriptor instead.
func (*GetCredentialResponse) Descriptor() ([]byte, []int) {
	return file_akssecuretlsbootstrap_v1_credential_proto_rawDescGZIP(), []int{1}
}

func (x *GetCredentialResponse) GetEncodedCertPem() string {
	if x != nil {
		return x.EncodedCertPem
	}
	return ""
}

var File_akssecuretlsbootstrap_v1_credential_proto protoreflect.FileDescriptor

var file_akssecuretlsbootstrap_v1_credential_proto_rawDesc = string([]byte{
	0x0a, 0x29, 0x61, 0x6b, 0x73, 0x73, 0x65, 0x63, 0x75, 0x72, 0x65, 0x74, 0x6c, 0x73, 0x62, 0x6f,
	0x6f, 0x74, 0x73, 0x74, 0x72, 0x61, 0x70, 0x2f, 0x76, 0x31, 0x2f, 0x63, 0x72, 0x65, 0x64, 0x65,
	0x6e, 0x74, 0x69, 0x61, 0x6c, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x18, 0x61, 0x6b, 0x73,
	0x73, 0x65, 0x63, 0x75, 0x72, 0x65, 0x74, 0x6c, 0x73, 0x62, 0x6f, 0x6f, 0x74, 0x73, 0x74, 0x72,
	0x61, 0x70, 0x2e, 0x76, 0x31, 0x1a, 0x0f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x6c, 0x6f, 0x67,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0xa6, 0x01, 0x0a, 0x14, 0x47, 0x65, 0x74, 0x43, 0x72,
	0x65, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x61, 0x6c, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12,
	0x1f, 0x0a, 0x0b, 0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x5f, 0x69, 0x64, 0x18, 0x01,
	0x20, 0x01, 0x28, 0x09, 0x52, 0x0a, 0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x49, 0x64,
	0x12, 0x14, 0x0a, 0x05, 0x6e, 0x6f, 0x6e, 0x63, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x05, 0x6e, 0x6f, 0x6e, 0x63, 0x65, 0x12, 0x29, 0x0a, 0x0d, 0x61, 0x74, 0x74, 0x65, 0x73, 0x74,
	0x65, 0x64, 0x5f, 0x64, 0x61, 0x74, 0x61, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x42, 0x04, 0x88,
	0xb5, 0x18, 0x00, 0x52, 0x0c, 0x61, 0x74, 0x74, 0x65, 0x73, 0x74, 0x65, 0x64, 0x44, 0x61, 0x74,
	0x61, 0x12, 0x2c, 0x0a, 0x0f, 0x65, 0x6e, 0x63, 0x6f, 0x64, 0x65, 0x64, 0x5f, 0x63, 0x73, 0x72,
	0x5f, 0x70, 0x65, 0x6d, 0x18, 0x04, 0x20, 0x01, 0x28, 0x09, 0x42, 0x04, 0x88, 0xb5, 0x18, 0x00,
	0x52, 0x0d, 0x65, 0x6e, 0x63, 0x6f, 0x64, 0x65, 0x64, 0x43, 0x73, 0x72, 0x50, 0x65, 0x6d, 0x22,
	0x47, 0x0a, 0x15, 0x47, 0x65, 0x74, 0x43, 0x72, 0x65, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x61, 0x6c,
	0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x2e, 0x0a, 0x10, 0x65, 0x6e, 0x63, 0x6f,
	0x64, 0x65, 0x64, 0x5f, 0x63, 0x65, 0x72, 0x74, 0x5f, 0x70, 0x65, 0x6d, 0x18, 0x01, 0x20, 0x01,
	0x28, 0x09, 0x42, 0x04, 0x88, 0xb5, 0x18, 0x00, 0x52, 0x0e, 0x65, 0x6e, 0x63, 0x6f, 0x64, 0x65,
	0x64, 0x43, 0x65, 0x72, 0x74, 0x50, 0x65, 0x6d, 0x42, 0xb6, 0x02, 0x0a, 0x1c, 0x63, 0x6f, 0x6d,
	0x2e, 0x61, 0x6b, 0x73, 0x73, 0x65, 0x63, 0x75, 0x72, 0x65, 0x74, 0x6c, 0x73, 0x62, 0x6f, 0x6f,
	0x74, 0x73, 0x74, 0x72, 0x61, 0x70, 0x2e, 0x76, 0x31, 0x42, 0x0f, 0x43, 0x72, 0x65, 0x64, 0x65,
	0x6e, 0x74, 0x69, 0x61, 0x6c, 0x50, 0x72, 0x6f, 0x74, 0x6f, 0x50, 0x01, 0x5a, 0x83, 0x01, 0x67,
	0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x41, 0x7a, 0x75, 0x72, 0x65, 0x2f,
	0x61, 0x6b, 0x73, 0x2d, 0x73, 0x65, 0x63, 0x75, 0x72, 0x65, 0x2d, 0x74, 0x6c, 0x73, 0x2d, 0x62,
	0x6f, 0x6f, 0x74, 0x73, 0x74, 0x72, 0x61, 0x70, 0x2f, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65,
	0x2f, 0x70, 0x6b, 0x67, 0x2f, 0x67, 0x65, 0x6e, 0x2f, 0x61, 0x6b, 0x73, 0x73, 0x65, 0x63, 0x75,
	0x72, 0x65, 0x74, 0x6c, 0x73, 0x62, 0x6f, 0x6f, 0x74, 0x73, 0x74, 0x72, 0x61, 0x70, 0x2f, 0x76,
	0x31, 0x2f, 0x61, 0x6b, 0x73, 0x73, 0x65, 0x63, 0x75, 0x72, 0x65, 0x74, 0x6c, 0x73, 0x62, 0x6f,
	0x6f, 0x74, 0x73, 0x74, 0x72, 0x61, 0x70, 0x2f, 0x76, 0x31, 0x3b, 0x61, 0x6b, 0x73, 0x73, 0x65,
	0x63, 0x75, 0x72, 0x65, 0x74, 0x6c, 0x73, 0x62, 0x6f, 0x6f, 0x74, 0x73, 0x74, 0x72, 0x61, 0x70,
	0x76, 0x31, 0xa2, 0x02, 0x03, 0x41, 0x58, 0x58, 0xaa, 0x02, 0x18, 0x41, 0x6b, 0x73, 0x73, 0x65,
	0x63, 0x75, 0x72, 0x65, 0x74, 0x6c, 0x73, 0x62, 0x6f, 0x6f, 0x74, 0x73, 0x74, 0x72, 0x61, 0x70,
	0x2e, 0x56, 0x31, 0xca, 0x02, 0x18, 0x41, 0x6b, 0x73, 0x73, 0x65, 0x63, 0x75, 0x72, 0x65, 0x74,
	0x6c, 0x73, 0x62, 0x6f, 0x6f, 0x74, 0x73, 0x74, 0x72, 0x61, 0x70, 0x5c, 0x56, 0x31, 0xe2, 0x02,
	0x24, 0x41, 0x6b, 0x73, 0x73, 0x65, 0x63, 0x75, 0x72, 0x65, 0x74, 0x6c, 0x73, 0x62, 0x6f, 0x6f,
	0x74, 0x73, 0x74, 0x72, 0x61, 0x70, 0x5c, 0x56, 0x31, 0x5c, 0x47, 0x50, 0x42, 0x4d, 0x65, 0x74,
	0x61, 0x64, 0x61, 0x74, 0x61, 0xea, 0x02, 0x19, 0x41, 0x6b, 0x73, 0x73, 0x65, 0x63, 0x75, 0x72,
	0x65, 0x74, 0x6c, 0x73, 0x62, 0x6f, 0x6f, 0x74, 0x73, 0x74, 0x72, 0x61, 0x70, 0x3a, 0x3a, 0x56,
	0x31, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
})

var (
	file_akssecuretlsbootstrap_v1_credential_proto_rawDescOnce sync.Once
	file_akssecuretlsbootstrap_v1_credential_proto_rawDescData []byte
)

func file_akssecuretlsbootstrap_v1_credential_proto_rawDescGZIP() []byte {
	file_akssecuretlsbootstrap_v1_credential_proto_rawDescOnce.Do(func() {
		file_akssecuretlsbootstrap_v1_credential_proto_rawDescData = protoimpl.X.CompressGZIP(unsafe.Slice(unsafe.StringData(file_akssecuretlsbootstrap_v1_credential_proto_rawDesc), len(file_akssecuretlsbootstrap_v1_credential_proto_rawDesc)))
	})
	return file_akssecuretlsbootstrap_v1_credential_proto_rawDescData
}

var file_akssecuretlsbootstrap_v1_credential_proto_msgTypes = make([]protoimpl.MessageInfo, 2)
var file_akssecuretlsbootstrap_v1_credential_proto_goTypes = []any{
	(*GetCredentialRequest)(nil),  // 0: akssecuretlsbootstrap.v1.GetCredentialRequest
	(*GetCredentialResponse)(nil), // 1: akssecuretlsbootstrap.v1.GetCredentialResponse
}
var file_akssecuretlsbootstrap_v1_credential_proto_depIdxs = []int32{
	0, // [0:0] is the sub-list for method output_type
	0, // [0:0] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_akssecuretlsbootstrap_v1_credential_proto_init() }
func file_akssecuretlsbootstrap_v1_credential_proto_init() {
	if File_akssecuretlsbootstrap_v1_credential_proto != nil {
		return
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: unsafe.Slice(unsafe.StringData(file_akssecuretlsbootstrap_v1_credential_proto_rawDesc), len(file_akssecuretlsbootstrap_v1_credential_proto_rawDesc)),
			NumEnums:      0,
			NumMessages:   2,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_akssecuretlsbootstrap_v1_credential_proto_goTypes,
		DependencyIndexes: file_akssecuretlsbootstrap_v1_credential_proto_depIdxs,
		MessageInfos:      file_akssecuretlsbootstrap_v1_credential_proto_msgTypes,
	}.Build()
	File_akssecuretlsbootstrap_v1_credential_proto = out.File
	file_akssecuretlsbootstrap_v1_credential_proto_goTypes = nil
	file_akssecuretlsbootstrap_v1_credential_proto_depIdxs = nil
}
