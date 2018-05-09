package main

import (
	"encoding/binary"
)

func uint16ToByte(value uint16) (b []byte) {
	b = make([]byte, 2)
	binary.BigEndian.PutUint16(b, uint16(value))
	return
}

func analyzeArp(buf []byte, num int) (err error) {
	// marshal arp header
	hardwareType := binary.BigEndian.Uint16(buf[:2])
	protoType := binary.BigEndian.Uint16(buf[2:4])
	macAddrLen := buf[4:5]
	ipAddrLen := buf[5:6]
	operationCode := binary.BigEndian.Uint16(buf[6:8])
	senderMacAddr := buf[8:14]
	senderIpAddr := buf[14:18]
	targetMacAddr := buf[18:24]
	targetIpAddr := buf[24:28]
	paddingData := buf[28:num]
	ah := &ArpHeader{
		HardwareType:  hardwareType,
		ProtoType:     protoType,
		MacAddrLen:    macAddrLen[0],
		IpAddrLen:     ipAddrLen[0],
		OperationCode: operationCode,
		SenderMacAddr: senderMacAddr,
		SenderIpAddr:  senderIpAddr,
		TargetMacAddr: targetMacAddr,
		TargetIpAddr:  targetIpAddr,
	}
	printArp(ah, paddingData)
	return nil
}

func analyzeIpv4(buf []byte, num int) (err error) {
	// marshal IP(v4) header
	var version, ihl, flags uint8
	var offset uint16
	version = buf[:1][0] >> 4
	ihl = buf[:1][0] << 4 >> 4
	serviceType := buf[1:2][0]
	totalLen := binary.BigEndian.Uint16(buf[2:4])
	identification := binary.BigEndian.Uint16(buf[4:6])
	flags = buf[6:7][0] >> 5
	offset = binary.BigEndian.Uint16(buf[6:8]) << 3 >> 3
	ttl := buf[8:9][0]
	nextProto := buf[9:10][0]
	checkSum := binary.BigEndian.Uint16(buf[10:12])
	srcIpAddr := buf[12:16]
	dstIpAddr := buf[16:20]
	upLayerData := buf[20:num]

	ih := &IpHeader{
		IpVersion:      version,
		HeaderLen:      ihl,
		ServiceType:    serviceType,
		TotalLen:       totalLen,
		Identification: identification,
		Flags:          flags,
		FragmentOffset: offset,
		TTL:            ttl,
		NextProto:      nextProto,
		CheckSum:       checkSum,
		SrcIpAddr:      srcIpAddr,
		DstIpAddr:      dstIpAddr,
	}

	// check ip protocol type and switch case
	switch ih.NextProto {
	case ProtoTypeIcmp:
		printIpv4(ih)
		err := analyzeIcmp(upLayerData, num)
		if err != nil {
			return err
		}

	case ProtoTypeTcp:
		printIpv4(ih)
		err := analyzeTcp(upLayerData, num)
		if err != nil {
			return err
		}

	case ProtoTypeUdp:
		printIpv4(ih)
		err := analyzeUdp(upLayerData, num)
		if err != nil {
			return err
		}

	default:
		printIpv4(ih)
	}
	return nil
}

func analyzeIpv6(buf []byte, num int) (err error) {
	// marshal IPv6 header
	var trafficClass uint16
	var flowLabel uint32
	ip6Version := buf[:1][0] >> 4
	trafficClass = binary.BigEndian.Uint16(buf[:2]) << 4 >> 8
	flowLabel = binary.BigEndian.Uint32(buf[:4]) << 12 >> 12
	payloadLen := binary.BigEndian.Uint16(buf[4:6])
	nextHeader := buf[6:7][0]
	hopLimit := buf[7:8][0]
	srcIp6Addr := buf[8:24]
	dstIp6Addr := buf[24:40]
	upLayerData := buf[40:num]

	ih6 := &Ipv6Header{
		Ipv6Version:  ip6Version,
		TrafficClass: trafficClass,
		FlowLabel:    flowLabel,
		PayloadLen:   payloadLen,
		NextHeader:   nextHeader,
		HopLimit:     hopLimit,
		SrcIpv6Addr:  srcIp6Addr,
		DstIpv6Addr:  dstIp6Addr,
	}

	// check ipv6 protocol type and switch case
	switch ih6.NextHeader {
	case NxtHeadIcmp6:
		printIpv6(ih6)
		err := analyzeIcmp(upLayerData, num)
		if err != nil {
			return err
		}

	case NxtHeadTcp:
		printIpv6(ih6)
		err := analyzeTcp(upLayerData, num)
		if err != nil {
			return err
		}

	case NxtHeadUdp:
		printIpv6(ih6)
		err := analyzeUdp(upLayerData, num)
		if err != nil {
			return err
		}

	default:
		printIpv6(ih6)
	}
	return nil
}

func analyzeIcmp(buf []byte, num int) (err error) {
	// marshal icmp header
	icmpType := buf[:1][0]
	icmpCode := buf[1:2][0]
	checkSum := binary.BigEndian.Uint16(buf[2:4])
	data := buf[4:num]

	icmph := &ICMPHeader{
		ICMPType: icmpType,
		ICMPCode: icmpCode,
		CheckSum: checkSum,
	}

	printIcmp(icmph, data)
	return nil
}

func analyzeTcp(buf []byte, num int) (err error) {
	// marshal tcp header
	var headerLen, ctrlFlag uint8
	var reservation uint16
	srcPort := binary.BigEndian.Uint16(buf[:2])
	dstPort := binary.BigEndian.Uint16(buf[2:4])
	seqNum := binary.BigEndian.Uint32(buf[4:8])
	ackNum := binary.BigEndian.Uint32(buf[8:12])
	headerLen = buf[12:13][0] >> 4
	reservation = binary.BigEndian.Uint16(buf[12:14]) << 4 >> 10
	ctrlFlag = buf[13:14][0] << 2 >> 2
	windowSize := binary.BigEndian.Uint16(buf[14:16])
	checkSum := binary.BigEndian.Uint16(buf[16:18])
	urgPointer := binary.BigEndian.Uint16(buf[18:20])
	data := buf[20:num]

	tcph := &TCPHeader{
		SrcPortNum:  srcPort,
		DstPortNum:  dstPort,
		SequenceNum: seqNum,
		AckNwlNum:   ackNum,
		HeaderLen:   headerLen,
		Reservation: reservation,
		CtrlFlag:    ctrlFlag,
		WindowSize:  windowSize,
		CheckSum:    checkSum,
		UrgPointer:  urgPointer,
	}

	printTcp(tcph, data)
	return nil
}

func analyzeUdp(buf []byte, num int) (err error) {
	// marshal udp header
	srcPort := binary.BigEndian.Uint16(buf[:2])
	dstPort := binary.BigEndian.Uint16(buf[2:4])
	packetLen := binary.BigEndian.Uint16(buf[4:6])
	checkSum := binary.BigEndian.Uint16(buf[6:8])
	data := buf[8:num]

	udph := &UDPHeader{
		SrcPortNum: srcPort,
		DstPortNum: dstPort,
		PacketLen:  packetLen,
		CheckSum:   checkSum,
	}

	printUdp(udph, data)
	return nil
}

func analyzePacket(buf []byte, num int) (err error) {
	// marshal ether header
	dstMacAddr := buf[:6]
	srcMacAddr := buf[6:12]
	protoType := binary.BigEndian.Uint16(buf[12:14])
	upLayerData := buf[14:num]
	eh := &EtherHeader{
		DstMacAddr: dstMacAddr,
		SrcMacAddr: srcMacAddr,
		ProtoType:  protoType,
	}

	// check ether protocol type and switch case
	switch eh.ProtoType {
	case EthTypeArp:
		printEther(eh)
		err := analyzeArp(upLayerData, num)
		if err != nil {
			return err
		}

	case EthTypeIpv4:
		printEther(eh)
		err := analyzeIpv4(upLayerData, num)
		if err != nil {
			return err
		}

	case EthTypeIpv6:
		printEther(eh)
		err := analyzeIpv6(upLayerData, num)
		if err != nil {
			return err
		}

	default:
		printEther(eh)
	}
	return nil
}
