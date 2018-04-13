package main

const (
	EthTypeIpv4 	= 0x0800
	EthTypeArp  	= 0x0806
	EthTypeAppTalk	= 0x809b
	EthTypeVlan		= 0x8100
	EthTypeIpx		= 0x8137
	EthTypeIpv6		= 0x86dd

	ProtoTypeIcmp	= 0x01
	ProtoTypeTcp	= 0x06
	ProtoTypeUdp	= 0x11

	NxtHeadIcmp6	= 0x3a
	NxtHeadTcp		= 0x06
	NxtHeadUdp		= 0x11

	IcmpEchoReply	= 0x00
	IcmpDstUnreach	= 0x03
	IcmpRedirect	= 0x05
	IcmpEchoReq		= 0x08
	IcmpExceeded	= 0x0b

	Icmp6DstUnreath	= 0x01
	Icmp6Echoreq	= 0x80
	Icmp6Echoreply	= 0x81
)
