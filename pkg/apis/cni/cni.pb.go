// Code generated by protoc-gen-go. DO NOT EDIT.
// source: apis/cni/cni.proto

package cnimsg

import (
	context "context"
	fmt "fmt"
	proto "github.com/golang/protobuf/proto"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
	math "math"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion3 // please upgrade the proto package

type CniCmdResponseMessage_ErrorCode int32

const (
	CniCmdResponseMessage_SUCCESS                           CniCmdResponseMessage_ErrorCode = 0
	CniCmdResponseMessage_INCOMPATIBLE_CNI_VERSION          CniCmdResponseMessage_ErrorCode = 1
	CniCmdResponseMessage_UNSUPPORTED_NETWORK_CONFIGURATION CniCmdResponseMessage_ErrorCode = 2
	CniCmdResponseMessage_UNKNOWN_CONTAINER                 CniCmdResponseMessage_ErrorCode = 3
	CniCmdResponseMessage_TRY_AGAIN_LATER                   CniCmdResponseMessage_ErrorCode = 11
	CniCmdResponseMessage_INCOMPATIBLE_PROTO_VERSION        CniCmdResponseMessage_ErrorCode = 100
	CniCmdResponseMessage_IPAM_FAILURE                      CniCmdResponseMessage_ErrorCode = 101
)

var CniCmdResponseMessage_ErrorCode_name = map[int32]string{
	0:   "SUCCESS",
	1:   "INCOMPATIBLE_CNI_VERSION",
	2:   "UNSUPPORTED_NETWORK_CONFIGURATION",
	3:   "UNKNOWN_CONTAINER",
	11:  "TRY_AGAIN_LATER",
	100: "INCOMPATIBLE_PROTO_VERSION",
	101: "IPAM_FAILURE",
}

var CniCmdResponseMessage_ErrorCode_value = map[string]int32{
	"SUCCESS":                           0,
	"INCOMPATIBLE_CNI_VERSION":          1,
	"UNSUPPORTED_NETWORK_CONFIGURATION": 2,
	"UNKNOWN_CONTAINER":                 3,
	"TRY_AGAIN_LATER":                   11,
	"INCOMPATIBLE_PROTO_VERSION":        100,
	"IPAM_FAILURE":                      101,
}

func (x CniCmdResponseMessage_ErrorCode) String() string {
	return proto.EnumName(CniCmdResponseMessage_ErrorCode_name, int32(x))
}

func (CniCmdResponseMessage_ErrorCode) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_d1df82b94f75833f, []int{2, 0}
}

type CniCmdArgsMessage struct {
	ContainerId          string   `protobuf:"bytes,1,opt,name=container_id,json=containerId,proto3" json:"container_id,omitempty"`
	Netns                string   `protobuf:"bytes,2,opt,name=netns,proto3" json:"netns,omitempty"`
	Ifname               string   `protobuf:"bytes,3,opt,name=ifname,proto3" json:"ifname,omitempty"`
	Args                 string   `protobuf:"bytes,4,opt,name=args,proto3" json:"args,omitempty"`
	Path                 string   `protobuf:"bytes,5,opt,name=path,proto3" json:"path,omitempty"`
	NetworkConfiguration []byte   `protobuf:"bytes,6,opt,name=network_configuration,json=networkConfiguration,proto3" json:"network_configuration,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *CniCmdArgsMessage) Reset()         { *m = CniCmdArgsMessage{} }
func (m *CniCmdArgsMessage) String() string { return proto.CompactTextString(m) }
func (*CniCmdArgsMessage) ProtoMessage()    {}
func (*CniCmdArgsMessage) Descriptor() ([]byte, []int) {
	return fileDescriptor_d1df82b94f75833f, []int{0}
}

func (m *CniCmdArgsMessage) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_CniCmdArgsMessage.Unmarshal(m, b)
}
func (m *CniCmdArgsMessage) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_CniCmdArgsMessage.Marshal(b, m, deterministic)
}
func (m *CniCmdArgsMessage) XXX_Merge(src proto.Message) {
	xxx_messageInfo_CniCmdArgsMessage.Merge(m, src)
}
func (m *CniCmdArgsMessage) XXX_Size() int {
	return xxx_messageInfo_CniCmdArgsMessage.Size(m)
}
func (m *CniCmdArgsMessage) XXX_DiscardUnknown() {
	xxx_messageInfo_CniCmdArgsMessage.DiscardUnknown(m)
}

var xxx_messageInfo_CniCmdArgsMessage proto.InternalMessageInfo

func (m *CniCmdArgsMessage) GetContainerId() string {
	if m != nil {
		return m.ContainerId
	}
	return ""
}

func (m *CniCmdArgsMessage) GetNetns() string {
	if m != nil {
		return m.Netns
	}
	return ""
}

func (m *CniCmdArgsMessage) GetIfname() string {
	if m != nil {
		return m.Ifname
	}
	return ""
}

func (m *CniCmdArgsMessage) GetArgs() string {
	if m != nil {
		return m.Args
	}
	return ""
}

func (m *CniCmdArgsMessage) GetPath() string {
	if m != nil {
		return m.Path
	}
	return ""
}

func (m *CniCmdArgsMessage) GetNetworkConfiguration() []byte {
	if m != nil {
		return m.NetworkConfiguration
	}
	return nil
}

type CniCmdRequestMessage struct {
	Version              string             `protobuf:"bytes,1,opt,name=version,proto3" json:"version,omitempty"`
	CniArgs              *CniCmdArgsMessage `protobuf:"bytes,2,opt,name=cni_args,json=cniArgs,proto3" json:"cni_args,omitempty"`
	XXX_NoUnkeyedLiteral struct{}           `json:"-"`
	XXX_unrecognized     []byte             `json:"-"`
	XXX_sizecache        int32              `json:"-"`
}

func (m *CniCmdRequestMessage) Reset()         { *m = CniCmdRequestMessage{} }
func (m *CniCmdRequestMessage) String() string { return proto.CompactTextString(m) }
func (*CniCmdRequestMessage) ProtoMessage()    {}
func (*CniCmdRequestMessage) Descriptor() ([]byte, []int) {
	return fileDescriptor_d1df82b94f75833f, []int{1}
}

func (m *CniCmdRequestMessage) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_CniCmdRequestMessage.Unmarshal(m, b)
}
func (m *CniCmdRequestMessage) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_CniCmdRequestMessage.Marshal(b, m, deterministic)
}
func (m *CniCmdRequestMessage) XXX_Merge(src proto.Message) {
	xxx_messageInfo_CniCmdRequestMessage.Merge(m, src)
}
func (m *CniCmdRequestMessage) XXX_Size() int {
	return xxx_messageInfo_CniCmdRequestMessage.Size(m)
}
func (m *CniCmdRequestMessage) XXX_DiscardUnknown() {
	xxx_messageInfo_CniCmdRequestMessage.DiscardUnknown(m)
}

var xxx_messageInfo_CniCmdRequestMessage proto.InternalMessageInfo

func (m *CniCmdRequestMessage) GetVersion() string {
	if m != nil {
		return m.Version
	}
	return ""
}

func (m *CniCmdRequestMessage) GetCniArgs() *CniCmdArgsMessage {
	if m != nil {
		return m.CniArgs
	}
	return nil
}

type CniCmdResponseMessage struct {
	Version              string                          `protobuf:"bytes,1,opt,name=version,proto3" json:"version,omitempty"`
	StatusCode           CniCmdResponseMessage_ErrorCode `protobuf:"varint,2,opt,name=status_code,json=statusCode,proto3,enum=cnimsg.CniCmdResponseMessage_ErrorCode" json:"status_code,omitempty"`
	CniResult            []byte                          `protobuf:"bytes,3,opt,name=cni_result,json=cniResult,proto3" json:"cni_result,omitempty"`
	ErrorMessage         string                          `protobuf:"bytes,4,opt,name=error_message,json=errorMessage,proto3" json:"error_message,omitempty"`
	XXX_NoUnkeyedLiteral struct{}                        `json:"-"`
	XXX_unrecognized     []byte                          `json:"-"`
	XXX_sizecache        int32                           `json:"-"`
}

func (m *CniCmdResponseMessage) Reset()         { *m = CniCmdResponseMessage{} }
func (m *CniCmdResponseMessage) String() string { return proto.CompactTextString(m) }
func (*CniCmdResponseMessage) ProtoMessage()    {}
func (*CniCmdResponseMessage) Descriptor() ([]byte, []int) {
	return fileDescriptor_d1df82b94f75833f, []int{2}
}

func (m *CniCmdResponseMessage) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_CniCmdResponseMessage.Unmarshal(m, b)
}
func (m *CniCmdResponseMessage) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_CniCmdResponseMessage.Marshal(b, m, deterministic)
}
func (m *CniCmdResponseMessage) XXX_Merge(src proto.Message) {
	xxx_messageInfo_CniCmdResponseMessage.Merge(m, src)
}
func (m *CniCmdResponseMessage) XXX_Size() int {
	return xxx_messageInfo_CniCmdResponseMessage.Size(m)
}
func (m *CniCmdResponseMessage) XXX_DiscardUnknown() {
	xxx_messageInfo_CniCmdResponseMessage.DiscardUnknown(m)
}

var xxx_messageInfo_CniCmdResponseMessage proto.InternalMessageInfo

func (m *CniCmdResponseMessage) GetVersion() string {
	if m != nil {
		return m.Version
	}
	return ""
}

func (m *CniCmdResponseMessage) GetStatusCode() CniCmdResponseMessage_ErrorCode {
	if m != nil {
		return m.StatusCode
	}
	return CniCmdResponseMessage_SUCCESS
}

func (m *CniCmdResponseMessage) GetCniResult() []byte {
	if m != nil {
		return m.CniResult
	}
	return nil
}

func (m *CniCmdResponseMessage) GetErrorMessage() string {
	if m != nil {
		return m.ErrorMessage
	}
	return ""
}

func init() {
	proto.RegisterEnum("cnimsg.CniCmdResponseMessage_ErrorCode", CniCmdResponseMessage_ErrorCode_name, CniCmdResponseMessage_ErrorCode_value)
	proto.RegisterType((*CniCmdArgsMessage)(nil), "cnimsg.CniCmdArgsMessage")
	proto.RegisterType((*CniCmdRequestMessage)(nil), "cnimsg.CniCmdRequestMessage")
	proto.RegisterType((*CniCmdResponseMessage)(nil), "cnimsg.CniCmdResponseMessage")
}

func init() { proto.RegisterFile("apis/cni/cni.proto", fileDescriptor_d1df82b94f75833f) }

var fileDescriptor_d1df82b94f75833f = []byte{
	// 520 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xa4, 0x53, 0xdd, 0x6e, 0xd3, 0x30,
	0x14, 0x5e, 0xf6, 0xd3, 0xad, 0xa7, 0x05, 0x32, 0xd3, 0xa2, 0x30, 0x6d, 0x68, 0x2b, 0x42, 0xec,
	0xaa, 0x48, 0x1d, 0x2f, 0x10, 0xbc, 0xac, 0x58, 0x6b, 0x9d, 0xca, 0x4d, 0x98, 0xb8, 0xb2, 0x42,
	0xe2, 0x76, 0xd6, 0x56, 0xa7, 0xd8, 0x29, 0x3c, 0x1c, 0x57, 0xbc, 0x0a, 0xef, 0x81, 0x84, 0x9c,
	0xb4, 0xd5, 0x36, 0x24, 0xb8, 0xd8, 0x45, 0xa4, 0x73, 0xbe, 0x93, 0xf3, 0x7d, 0xe7, 0x7c, 0x47,
	0x06, 0x94, 0xcc, 0xa5, 0x79, 0x97, 0x2a, 0x69, 0xbf, 0xee, 0x5c, 0xe7, 0x45, 0x8e, 0x6a, 0xa9,
	0x92, 0x33, 0x33, 0xed, 0xfc, 0x74, 0x60, 0x1f, 0x2b, 0x89, 0x67, 0x99, 0xaf, 0xa7, 0x66, 0x28,
	0x8c, 0x49, 0xa6, 0x02, 0x9d, 0x40, 0x33, 0xcd, 0x55, 0x91, 0x48, 0x25, 0x34, 0x97, 0x99, 0xe7,
	0x1c, 0x3b, 0xa7, 0x75, 0xd6, 0x58, 0x63, 0x24, 0x43, 0x2d, 0xd8, 0x51, 0xa2, 0x50, 0xc6, 0xdb,
	0x2c, 0x6b, 0x55, 0x82, 0x5e, 0x40, 0x4d, 0x4e, 0x54, 0x32, 0x13, 0xde, 0x56, 0x09, 0x2f, 0x33,
	0x84, 0x60, 0x3b, 0xd1, 0x53, 0xe3, 0x6d, 0x97, 0x68, 0x19, 0x5b, 0x6c, 0x9e, 0x14, 0xd7, 0xde,
	0x4e, 0x85, 0xd9, 0x18, 0x9d, 0x41, 0x5b, 0x89, 0xe2, 0x7b, 0xae, 0x6f, 0x78, 0x9a, 0xab, 0x89,
	0x9c, 0x2e, 0x74, 0x52, 0xc8, 0x5c, 0x79, 0xb5, 0x63, 0xe7, 0xb4, 0xc9, 0x5a, 0xcb, 0x22, 0xbe,
	0x5b, 0xeb, 0x4c, 0xa0, 0x55, 0xad, 0xc0, 0xc4, 0xd7, 0x85, 0x30, 0xc5, 0x6a, 0x0b, 0x0f, 0x76,
	0xbf, 0x09, 0x6d, 0x6c, 0x7b, 0xb5, 0xc0, 0x2a, 0x45, 0xef, 0x61, 0x2f, 0x55, 0x92, 0x97, 0x23,
	0xd9, 0xf9, 0x1b, 0xbd, 0x97, 0xdd, 0xca, 0x90, 0xee, 0x5f, 0x66, 0xb0, 0xdd, 0x54, 0x49, 0x9b,
	0x77, 0x7e, 0x6f, 0x42, 0x7b, 0x25, 0x64, 0xe6, 0xb9, 0x32, 0xe2, 0xff, 0x4a, 0x1f, 0xa1, 0x61,
	0x8a, 0xa4, 0x58, 0x18, 0x9e, 0xe6, 0x99, 0x28, 0xc5, 0x9e, 0xf6, 0xde, 0xde, 0x17, 0x7b, 0xc0,
	0xd6, 0x0d, 0xb4, 0xce, 0x35, 0xce, 0x33, 0xc1, 0xa0, 0xea, 0xb5, 0x31, 0x3a, 0x02, 0xb0, 0x33,
	0x6b, 0x61, 0x16, 0xb7, 0x45, 0x69, 0x6f, 0x93, 0xd5, 0x53, 0x25, 0x59, 0x09, 0xa0, 0xd7, 0xf0,
	0x44, 0xd8, 0x3e, 0x3e, 0xab, 0x58, 0x96, 0x56, 0x37, 0x4b, 0x70, 0xc9, 0xdc, 0xf9, 0xe1, 0x40,
	0x7d, 0xcd, 0x8e, 0x1a, 0xb0, 0x3b, 0x8e, 0x31, 0x0e, 0xc6, 0x63, 0x77, 0x03, 0x1d, 0x82, 0x47,
	0x28, 0x0e, 0x87, 0x23, 0x3f, 0x22, 0x1f, 0x06, 0x01, 0xc7, 0x94, 0xf0, 0x4f, 0x01, 0x1b, 0x93,
	0x90, 0xba, 0x0e, 0x7a, 0x03, 0x27, 0x31, 0x1d, 0xc7, 0xa3, 0x51, 0xc8, 0xa2, 0xe0, 0x9c, 0xd3,
	0x20, 0xba, 0x0a, 0xd9, 0x25, 0xc7, 0x21, 0xbd, 0x20, 0xfd, 0x98, 0xf9, 0x91, 0xfd, 0x6d, 0x13,
	0xb5, 0x61, 0x3f, 0xa6, 0x97, 0x34, 0xbc, 0xa2, 0xb6, 0x14, 0xf9, 0x84, 0x06, 0xcc, 0xdd, 0x42,
	0xcf, 0xe1, 0x59, 0xc4, 0x3e, 0x73, 0xbf, 0xef, 0x13, 0xca, 0x07, 0x7e, 0x14, 0x30, 0xb7, 0x81,
	0x5e, 0xc1, 0xc1, 0x3d, 0xc1, 0x11, 0x0b, 0xa3, 0x70, 0x2d, 0x99, 0x21, 0x17, 0x9a, 0x64, 0xe4,
	0x0f, 0xf9, 0x85, 0x4f, 0x06, 0x31, 0x0b, 0x5c, 0xd1, 0xfb, 0xe5, 0xc0, 0x16, 0x56, 0x12, 0xf5,
	0xa1, 0x66, 0x4f, 0x94, 0x65, 0xe8, 0xf0, 0xa1, 0x91, 0x77, 0xef, 0x7f, 0x70, 0xf4, 0x4f, 0x9b,
	0x3b, 0x1b, 0x88, 0xc0, 0x1e, 0x9e, 0x65, 0xf8, 0x5a, 0xa4, 0x37, 0x8f, 0xa5, 0xaa, 0x66, 0x3a,
	0x17, 0xb7, 0x8f, 0x24, 0xfa, 0x52, 0x2b, 0xdf, 0xe7, 0xd9, 0x9f, 0x00, 0x00, 0x00, 0xff, 0xff,
	0xb0, 0x6e, 0xeb, 0x20, 0xb5, 0x03, 0x00, 0x00,
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConn

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion4

// CniClient is the client API for Cni service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://godoc.org/google.golang.org/grpc#ClientConn.NewStream.
type CniClient interface {
	CmdAdd(ctx context.Context, in *CniCmdRequestMessage, opts ...grpc.CallOption) (*CniCmdResponseMessage, error)
	CmdCheck(ctx context.Context, in *CniCmdRequestMessage, opts ...grpc.CallOption) (*CniCmdResponseMessage, error)
	CmdDel(ctx context.Context, in *CniCmdRequestMessage, opts ...grpc.CallOption) (*CniCmdResponseMessage, error)
}

type cniClient struct {
	cc *grpc.ClientConn
}

func NewCniClient(cc *grpc.ClientConn) CniClient {
	return &cniClient{cc}
}

func (c *cniClient) CmdAdd(ctx context.Context, in *CniCmdRequestMessage, opts ...grpc.CallOption) (*CniCmdResponseMessage, error) {
	out := new(CniCmdResponseMessage)
	err := c.cc.Invoke(ctx, "/cnimsg.Cni/CmdAdd", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *cniClient) CmdCheck(ctx context.Context, in *CniCmdRequestMessage, opts ...grpc.CallOption) (*CniCmdResponseMessage, error) {
	out := new(CniCmdResponseMessage)
	err := c.cc.Invoke(ctx, "/cnimsg.Cni/CmdCheck", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *cniClient) CmdDel(ctx context.Context, in *CniCmdRequestMessage, opts ...grpc.CallOption) (*CniCmdResponseMessage, error) {
	out := new(CniCmdResponseMessage)
	err := c.cc.Invoke(ctx, "/cnimsg.Cni/CmdDel", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// CniServer is the server API for Cni service.
type CniServer interface {
	CmdAdd(context.Context, *CniCmdRequestMessage) (*CniCmdResponseMessage, error)
	CmdCheck(context.Context, *CniCmdRequestMessage) (*CniCmdResponseMessage, error)
	CmdDel(context.Context, *CniCmdRequestMessage) (*CniCmdResponseMessage, error)
}

// UnimplementedCniServer can be embedded to have forward compatible implementations.
type UnimplementedCniServer struct {
}

func (*UnimplementedCniServer) CmdAdd(ctx context.Context, req *CniCmdRequestMessage) (*CniCmdResponseMessage, error) {
	return nil, status.Errorf(codes.Unimplemented, "method CmdAdd not implemented")
}
func (*UnimplementedCniServer) CmdCheck(ctx context.Context, req *CniCmdRequestMessage) (*CniCmdResponseMessage, error) {
	return nil, status.Errorf(codes.Unimplemented, "method CmdCheck not implemented")
}
func (*UnimplementedCniServer) CmdDel(ctx context.Context, req *CniCmdRequestMessage) (*CniCmdResponseMessage, error) {
	return nil, status.Errorf(codes.Unimplemented, "method CmdDel not implemented")
}

func RegisterCniServer(s *grpc.Server, srv CniServer) {
	s.RegisterService(&_Cni_serviceDesc, srv)
}

func _Cni_CmdAdd_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(CniCmdRequestMessage)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(CniServer).CmdAdd(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/cnimsg.Cni/CmdAdd",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(CniServer).CmdAdd(ctx, req.(*CniCmdRequestMessage))
	}
	return interceptor(ctx, in, info, handler)
}

func _Cni_CmdCheck_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(CniCmdRequestMessage)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(CniServer).CmdCheck(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/cnimsg.Cni/CmdCheck",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(CniServer).CmdCheck(ctx, req.(*CniCmdRequestMessage))
	}
	return interceptor(ctx, in, info, handler)
}

func _Cni_CmdDel_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(CniCmdRequestMessage)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(CniServer).CmdDel(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/cnimsg.Cni/CmdDel",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(CniServer).CmdDel(ctx, req.(*CniCmdRequestMessage))
	}
	return interceptor(ctx, in, info, handler)
}

var _Cni_serviceDesc = grpc.ServiceDesc{
	ServiceName: "cnimsg.Cni",
	HandlerType: (*CniServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "CmdAdd",
			Handler:    _Cni_CmdAdd_Handler,
		},
		{
			MethodName: "CmdCheck",
			Handler:    _Cni_CmdCheck_Handler,
		},
		{
			MethodName: "CmdDel",
			Handler:    _Cni_CmdDel_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "apis/cni/cni.proto",
}
