//
// Copyright 2025 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.5.1
// - protoc             v5.28.3
// source: key_transparency.proto

package pb

import (
	context "context"
	pb "github.com/signalapp/keytransparency/tree/transparency/pb"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
	emptypb "google.golang.org/protobuf/types/known/emptypb"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.64.0 or later.
const _ = grpc.SupportPackageIsVersion9

const (
	KeyTransparencyService_Audit_FullMethodName          = "/kt.KeyTransparencyService/Audit"
	KeyTransparencyService_SetAuditorHead_FullMethodName = "/kt.KeyTransparencyService/SetAuditorHead"
)

// KeyTransparencyServiceClient is the client API for KeyTransparencyService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
//
// A key transparency service used to update the transparency log and to accept auditor-signed tree heads.
// With the exception of the third-party auditor, this service's endpoints are *not* intended to be used by external clients.
// It is exposed to the public internet by necessity but will reject calls from unauthenticated callers.
type KeyTransparencyServiceClient interface {
	// Auditors use this endpoint to request a batch of key transparency service updates to audit.
	Audit(ctx context.Context, in *AuditRequest, opts ...grpc.CallOption) (*AuditResponse, error)
	// Auditors use this endpoint to return a signature on the log tree root hash corresponding to the last audited update.
	SetAuditorHead(ctx context.Context, in *pb.AuditorTreeHead, opts ...grpc.CallOption) (*emptypb.Empty, error)
}

type keyTransparencyServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewKeyTransparencyServiceClient(cc grpc.ClientConnInterface) KeyTransparencyServiceClient {
	return &keyTransparencyServiceClient{cc}
}

func (c *keyTransparencyServiceClient) Audit(ctx context.Context, in *AuditRequest, opts ...grpc.CallOption) (*AuditResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(AuditResponse)
	err := c.cc.Invoke(ctx, KeyTransparencyService_Audit_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *keyTransparencyServiceClient) SetAuditorHead(ctx context.Context, in *pb.AuditorTreeHead, opts ...grpc.CallOption) (*emptypb.Empty, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(emptypb.Empty)
	err := c.cc.Invoke(ctx, KeyTransparencyService_SetAuditorHead_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// KeyTransparencyServiceServer is the server API for KeyTransparencyService service.
// All implementations must embed UnimplementedKeyTransparencyServiceServer
// for forward compatibility.
//
// A key transparency service used to update the transparency log and to accept auditor-signed tree heads.
// With the exception of the third-party auditor, this service's endpoints are *not* intended to be used by external clients.
// It is exposed to the public internet by necessity but will reject calls from unauthenticated callers.
type KeyTransparencyServiceServer interface {
	// Auditors use this endpoint to request a batch of key transparency service updates to audit.
	Audit(context.Context, *AuditRequest) (*AuditResponse, error)
	// Auditors use this endpoint to return a signature on the log tree root hash corresponding to the last audited update.
	SetAuditorHead(context.Context, *pb.AuditorTreeHead) (*emptypb.Empty, error)
	mustEmbedUnimplementedKeyTransparencyServiceServer()
}

// UnimplementedKeyTransparencyServiceServer must be embedded to have
// forward compatible implementations.
//
// NOTE: this should be embedded by value instead of pointer to avoid a nil
// pointer dereference when methods are called.
type UnimplementedKeyTransparencyServiceServer struct{}

func (UnimplementedKeyTransparencyServiceServer) Audit(context.Context, *AuditRequest) (*AuditResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Audit not implemented")
}
func (UnimplementedKeyTransparencyServiceServer) SetAuditorHead(context.Context, *pb.AuditorTreeHead) (*emptypb.Empty, error) {
	return nil, status.Errorf(codes.Unimplemented, "method SetAuditorHead not implemented")
}
func (UnimplementedKeyTransparencyServiceServer) mustEmbedUnimplementedKeyTransparencyServiceServer() {
}
func (UnimplementedKeyTransparencyServiceServer) testEmbeddedByValue() {}

// UnsafeKeyTransparencyServiceServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to KeyTransparencyServiceServer will
// result in compilation errors.
type UnsafeKeyTransparencyServiceServer interface {
	mustEmbedUnimplementedKeyTransparencyServiceServer()
}

func RegisterKeyTransparencyServiceServer(s grpc.ServiceRegistrar, srv KeyTransparencyServiceServer) {
	// If the following call pancis, it indicates UnimplementedKeyTransparencyServiceServer was
	// embedded by pointer and is nil.  This will cause panics if an
	// unimplemented method is ever invoked, so we test this at initialization
	// time to prevent it from happening at runtime later due to I/O.
	if t, ok := srv.(interface{ testEmbeddedByValue() }); ok {
		t.testEmbeddedByValue()
	}
	s.RegisterService(&KeyTransparencyService_ServiceDesc, srv)
}

func _KeyTransparencyService_Audit_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(AuditRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(KeyTransparencyServiceServer).Audit(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: KeyTransparencyService_Audit_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(KeyTransparencyServiceServer).Audit(ctx, req.(*AuditRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _KeyTransparencyService_SetAuditorHead_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(pb.AuditorTreeHead)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(KeyTransparencyServiceServer).SetAuditorHead(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: KeyTransparencyService_SetAuditorHead_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(KeyTransparencyServiceServer).SetAuditorHead(ctx, req.(*pb.AuditorTreeHead))
	}
	return interceptor(ctx, in, info, handler)
}

// KeyTransparencyService_ServiceDesc is the grpc.ServiceDesc for KeyTransparencyService service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var KeyTransparencyService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "kt.KeyTransparencyService",
	HandlerType: (*KeyTransparencyServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "Audit",
			Handler:    _KeyTransparencyService_Audit_Handler,
		},
		{
			MethodName: "SetAuditorHead",
			Handler:    _KeyTransparencyService_SetAuditorHead_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "key_transparency.proto",
}
