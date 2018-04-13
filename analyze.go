package main

import (
	"fmt"
	"encoding/binary"
)

func uint16ToByte(value uint16) (b []byte, err error) {
	b = make([]byte, 2)
	binary.BigEndian.PutUint16(b, uint16(value))
	return
}

func analyzeArp(e *EtherHeader, buf []byte) (err error) {
	return nil
}

func analyzeIpv4(e *EtherHeader, buf []byte) (err error) {
	return nil
}

func analyzeIpv6(e *EtherHeader, buf []byte) (err error) {
	return nil
}

func analyzePacket(buf []byte, num int) (err error) {
	dstMacAddr := buf[:6]
	srcMacAddr := buf[6:12]
	protoType := binary.BigEndian.Uint16(buf[12:14])
	e := &EtherHeader{
		DstMacAddr: dstMacAddr,
		SrcMacAddr: srcMacAddr,
		ProtoType: protoType,
	}
	upLayerData := buf[12:num]

	b, err := uint16ToByte(e.ProtoType)
	if err != nil {
		return err
	}

	//Debug Print
	fmt.Printf("-------------Ether-------------\n")
	fmt.Println("Dst: ", e.DstMacAddr)
	fmt.Println("Src: ", e.SrcMacAddr)
	fmt.Printf("Type: %X\n", b)
	fmt.Printf("UpLayerData: %X\n", upLayerData)
	fmt.Printf("-------------------------------\n")

	//switch e.ProtoType {
	//case EthTypeArp:
	//	analyzeArp(e, upLayerData)
	//
	//case EthTypeIpv4:
	//	analyzeIpv4(e, upLayerData)
	//
	//case EthTypeIpv6:
	//	analyzeIpv6(e, upLayerData)
	//}
	return nil
}
