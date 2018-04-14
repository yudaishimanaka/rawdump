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
		HardwareType: hardwareType,
		ProtoType: protoType,
		MacAddrLen: macAddrLen[0],
		IpAddrLen: ipAddrLen[0],
		OperationCode: operationCode,
		SenderMacAddr: senderMacAddr,
		SenderIpAddr: senderIpAddr,
		TargetMacAddr: targetMacAddr,
		TargetIpAddr: targetIpAddr,
	}
	printArp(ah, paddingData)
	return nil
}

func analyzeIpv4(buf []byte, num int) (err error) {
	return nil
}

func analyzeIpv6(buf []byte, num int) (err error) {
	return nil
}

func analyzePacket(buf []byte, num int) (err error) {
	dstMacAddr := buf[:6]
	srcMacAddr := buf[6:12]
	protoType := binary.BigEndian.Uint16(buf[12:14])
	upLayerData := buf[14:num]
	eh := &EtherHeader{
		DstMacAddr: dstMacAddr,
		SrcMacAddr: srcMacAddr,
		ProtoType: protoType,
	}

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
