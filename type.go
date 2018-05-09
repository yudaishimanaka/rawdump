package main

const (
	EthTypeIpv4    uint16 = 0x0800
	EthTypeArp     uint16 = 0x0806
	EthTypeAppTalk uint16 = 0x809b
	EthTypeVlan    uint16 = 0x8100
	EthTypeIpx     uint16 = 0x8137
	EthTypeIpv6    uint16 = 0x86dd

	OpCodeRequest uint16 = 0x0001
	OpCodeReply   uint16 = 0x0002
	OpCodeReqRev  uint16 = 0x0003
	OpCodeRepRev  uint16 = 0x0004

	ProtoTypeIcmp uint8 = 0x01
	ProtoTypeTcp  uint8 = 0x06
	ProtoTypeUdp  uint8 = 0x11

	NxtHeadIcmp6 uint8 = 0x3a
	NxtHeadTcp   uint8 = 0x06
	NxtHeadUdp   uint8 = 0x11

	IcmpEchoReply  uint8 = 0x00
	IcmpDstUnreach uint8 = 0x03
	IcmpRedirect   uint8 = 0x05
	IcmpEchoReq    uint8 = 0x08
	IcmpExceeded   uint8 = 0x0b

	Icmp6DstUnreath uint8 = 0x01
	Icmp6Echoreq    uint8 = 0x80
	Icmp6Echoreply  uint8 = 0x81
)
