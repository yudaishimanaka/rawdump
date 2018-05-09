package main

import (
	"net"
)

type EtherHeader struct {
	DstMacAddr net.HardwareAddr
	SrcMacAddr net.HardwareAddr
	ProtoType  uint16
}

type ArpHeader struct {
	HardwareType  uint16
	ProtoType     uint16
	MacAddrLen    uint8
	IpAddrLen     uint8
	OperationCode uint16
	SenderMacAddr net.HardwareAddr
	SenderIpAddr  net.IP
	TargetMacAddr net.HardwareAddr
	TargetIpAddr  net.IP
}

type IpHeader struct {
	IpVersion      uint8
	HeaderLen      uint8
	ServiceType    uint8
	TotalLen       uint16
	Identification uint16
	Flags          uint8
	FragmentOffset uint16
	TTL            uint8
	NextProto      uint8
	CheckSum       uint16
	SrcIpAddr      net.IP
	DstIpAddr      net.IP
}

type Ipv6Header struct {
	Ipv6Version  uint8
	TrafficClass uint16
	FlowLabel    uint32
	PayloadLen   uint16
	NextHeader   uint8
	HopLimit     uint8
	SrcIpv6Addr  net.IP
	DstIpv6Addr  net.IP
}

type ICMPHeader struct {
	ICMPType uint8
	ICMPCode uint8
	CheckSum uint16
}

type TCPHeader struct {
	SrcPortNum  uint16
	DstPortNum  uint16
	SequenceNum uint32
	AckNwlNum   uint32
	HeaderLen   uint8
	Reservation	uint16
	CtrlFlag    uint8
	WindowSize  uint16
	CheckSum    uint16
	UrgPointer  uint16
}

type UDPHeader struct {
	SrcPortNum uint16
	DstPortNum uint16
	PacketLen  uint16
	CheckSum   uint16
}
