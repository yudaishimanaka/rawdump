package main

const (
	EthTypeIpv4    uint16 = 0x0800
	EthTypeArp     uint16 = 0x0806
	EthTypeAppTalk uint16 = 0x809b
	EthTypeVlan    uint16 = 0x8100
	EthTypeIpx     uint16 = 0x8137
	EthTypeIpv6    uint16 = 0x86dd

	ArpProtoType	uint16 = 0x0800

	OpCodeRequest	uint16 = 0x0001
	OpCodeReply		uint16 = 0x0002
	OpCodeReqRev	uint16 = 0x0003
	OpCodeRepRev	uint16 = 0x0004

	ProtoTypeIcmp uint16 = 0x01
	ProtoTypeTcp  uint16 = 0x06
	ProtoTypeUdp  uint16 = 0x11

	NxtHeadIcmp6 uint16 = 0x3a
	NxtHeadTcp   uint16 = 0x06
	NxtHeadUdp   uint16 = 0x11

	IcmpEchoReply  uint16 = 0x00
	IcmpDstUnreach uint16 = 0x03
	IcmpRedirect   uint16 = 0x05
	IcmpEchoReq    uint16 = 0x08
	IcmpExceeded   uint16 = 0x0b

	Icmp6DstUnreath uint16 = 0x01
	Icmp6Echoreq    uint16 = 0x80
	Icmp6Echoreply  uint16 = 0x81
)
