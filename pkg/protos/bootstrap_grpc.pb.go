// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.3.0
// - protoc             v4.24.3
// source: pkg/protos/bootstrap.proto

package protos

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.32.0 or later.
const _ = grpc.SupportPackageIsVersion7

const (
	AKSBootstrapTokenRequest_GetNonce_FullMethodName      = "/azure.aks.tlsbootstrap.AKSBootstrapTokenRequest/GetNonce"
	AKSBootstrapTokenRequest_GetCredential_FullMethodName = "/azure.aks.tlsbootstrap.AKSBootstrapTokenRequest/GetCredential"
)

// AKSBootstrapTokenRequestClient is the client API for AKSBootstrapTokenRequest service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type AKSBootstrapTokenRequestClient interface {
	SetGRPCConnection(conn *grpc.ClientConn)

	// Step 1 of retrieving a bootstrap token; generates a nonce to be used by the
	// client when requesting attested data.
	GetNonce(ctx context.Context, in *NonceRequest, opts ...grpc.CallOption) (*NonceResponse, error)
	// Step 2 of retrieving a bootstrap token; validates the attested data and the
	// nonce, then generates and returns the bootstrap token to the client.
	GetCredential(ctx context.Context, in *CredentialRequest, opts ...grpc.CallOption) (*CredentialResponse, error)
}

type aKSBootstrapTokenRequestClient struct {
	cc grpc.ClientConnInterface
}

func NewAKSBootstrapTokenRequestClient() AKSBootstrapTokenRequestClient {
	return &aKSBootstrapTokenRequestClient{}
}

func (c *aKSBootstrapTokenRequestClient) SetGRPCConnection(conn *grpc.ClientConn) {
	c.cc = conn
}

func (c *aKSBootstrapTokenRequestClient) GetNonce(ctx context.Context, in *NonceRequest, opts ...grpc.CallOption) (*NonceResponse, error) {
	out := new(NonceResponse)
	err := c.cc.Invoke(ctx, AKSBootstrapTokenRequest_GetNonce_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *aKSBootstrapTokenRequestClient) GetCredential(ctx context.Context, in *CredentialRequest, opts ...grpc.CallOption) (*CredentialResponse, error) {
	out := new(CredentialResponse)
	err := c.cc.Invoke(ctx, AKSBootstrapTokenRequest_GetCredential_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// AKSBootstrapTokenRequestServer is the server API for AKSBootstrapTokenRequest service.
// All implementations must embed UnimplementedAKSBootstrapTokenRequestServer
// for forward compatibility
type AKSBootstrapTokenRequestServer interface {
	// Step 1 of retrieving a bootstrap token; generates a nonce to be used by the
	// client when requesting attested data.
	GetNonce(context.Context, *NonceRequest) (*NonceResponse, error)
	// Step 2 of retrieving a bootstrap token; validates the attested data and the
	// nonce, then generates and returns the bootstrap token to the client.
	GetCredential(context.Context, *CredentialRequest) (*CredentialResponse, error)
	mustEmbedUnimplementedAKSBootstrapTokenRequestServer()
}

// UnimplementedAKSBootstrapTokenRequestServer must be embedded to have forward compatible implementations.
type UnimplementedAKSBootstrapTokenRequestServer struct {
}

func (UnimplementedAKSBootstrapTokenRequestServer) GetNonce(context.Context, *NonceRequest) (*NonceResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetNonce not implemented")
}
func (UnimplementedAKSBootstrapTokenRequestServer) GetCredential(context.Context, *CredentialRequest) (*CredentialResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetCredential not implemented")
}
func (UnimplementedAKSBootstrapTokenRequestServer) mustEmbedUnimplementedAKSBootstrapTokenRequestServer() {
}

// UnsafeAKSBootstrapTokenRequestServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to AKSBootstrapTokenRequestServer will
// result in compilation errors.
type UnsafeAKSBootstrapTokenRequestServer interface {
	mustEmbedUnimplementedAKSBootstrapTokenRequestServer()
}

func RegisterAKSBootstrapTokenRequestServer(s grpc.ServiceRegistrar, srv AKSBootstrapTokenRequestServer) {
	s.RegisterService(&AKSBootstrapTokenRequest_ServiceDesc, srv)
}

func _AKSBootstrapTokenRequest_GetNonce_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(NonceRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AKSBootstrapTokenRequestServer).GetNonce(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: AKSBootstrapTokenRequest_GetNonce_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AKSBootstrapTokenRequestServer).GetNonce(ctx, req.(*NonceRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _AKSBootstrapTokenRequest_GetCredential_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(CredentialRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AKSBootstrapTokenRequestServer).GetCredential(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: AKSBootstrapTokenRequest_GetCredential_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AKSBootstrapTokenRequestServer).GetCredential(ctx, req.(*CredentialRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// AKSBootstrapTokenRequest_ServiceDesc is the grpc.ServiceDesc for AKSBootstrapTokenRequest service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var AKSBootstrapTokenRequest_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "azure.aks.tlsbootstrap.AKSBootstrapTokenRequest",
	HandlerType: (*AKSBootstrapTokenRequestServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "GetNonce",
			Handler:    _AKSBootstrapTokenRequest_GetNonce_Handler,
		},
		{
			MethodName: "GetCredential",
			Handler:    _AKSBootstrapTokenRequest_GetCredential_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "pkg/protos/bootstrap.proto",
}
