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

	// link type
	LinkTypeNull           uint8 = 0
	LinkTypeEthernet       uint8 = 1
	LinkTypeAX25           uint8 = 3
	LinkTypeTokenRing      uint8 = 6
	LinkTypeArcNet         uint8 = 7
	LinkTypeSLIP           uint8 = 8
	LinkTypePPP            uint8 = 9
	LinkTypeFDDI           uint8 = 10
	LinkTypePPP_HDLC       uint8 = 50
	LinkTypePPPEthernet    uint8 = 51
	LinkTypeATM_RFC1483    uint8 = 100
	LinkTypeRaw            uint8 = 101
	LinkTypeC_HDLC         uint8 = 104
	LinkTypeIEEE802_11     uint8 = 105
	LinkTypeFRelay         uint8 = 107
	LinkTypeLoop           uint8 = 108
	LinkTypeLinuxSLL       uint8 = 113
	LinkTypeLTalk          uint8 = 114
	LinkTypePFLog          uint8 = 117
	LinkTypePrismHeader    uint8 = 119
	LinkTypeIPOverFC       uint8 = 122
	LinkTypeSunATM         uint8 = 123
	LinkTypeIEEE80211Radio uint8 = 127
	LinkTypeARCNetLinux    uint8 = 129
	LinkTypeIPOver1394     uint8 = 138
	LinkTypeMTP2Phdr       uint8 = 139
	LinkTypeMTP2           uint8 = 140
	LinkTypeMTP3           uint8 = 141
	LinkTypeSCCP           uint8 = 142
	LinkTypeDOCSIS         uint8 = 143
	LinkTypeLinuxIRDA      uint8 = 144
	LinkTypeLinuxLAPD      uint8 = 177
	LinkTypeLinuxUSB       uint8 = 220
	LinkTypeIPv4           uint8 = 228
	LinkTypeIPv6           uint8 = 229
)
