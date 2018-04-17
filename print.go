package main

import (
	"fmt"
)

func printUnknown(uh []byte) {
	// print unknown header and data
}

func printEther(eh *EtherHeader) {
	// print ether header
	fmt.Printf("-------------Ether-------------\n")
	fmt.Println("Dst: ", eh.DstMacAddr)
	fmt.Println("Src: ", eh.SrcMacAddr)
	t := uint16ToByte(eh.ProtoType)
	switch eh.ProtoType {
	case EthTypeArp:
		fmt.Printf("Type: ARP(%X)\n", t)

	case EthTypeIpv4:
		fmt.Printf("Type: IP(%X)\n", t)

	case EthTypeIpv6:
		fmt.Printf("Type: IPv6(%X)\n", t)

	default:
		fmt.Printf("Type: Unknown(%X)\n", t)
	}
	fmt.Printf("-------------------------------\n")
}

func printArp(ah *ArpHeader, pd []byte) {
	// print arp header and padding data
	t := uint16ToByte(ah.ProtoType)
	fmt.Printf("--------------Arp--------------\n")
	fmt.Printf("HardwareType: %X\n", ah.HardwareType)
	fmt.Printf("ProtoType: IP(%X)\n", t)
	fmt.Printf("MacAddrLen: %X\n", ah.MacAddrLen)
	fmt.Printf("IpAddrLen: %X\n", ah.IpAddrLen)
	switch ah.OperationCode {
	case OpCodeRequest:
		fmt.Printf("OprationCode: %X(request)\n", ah.OperationCode)

	case OpCodeReply:
		fmt.Printf("OprationCode: %X(reply)\n", ah.OperationCode)

	case OpCodeReqRev:
		fmt.Printf("OprationCode: %X(request reverse)\n", ah.OperationCode)

	case OpCodeRepRev:
		fmt.Printf("OprationCode: %X(reply reverse)\n", ah.OperationCode)

	default:
		fmt.Printf("OprationCode: %X(Unknown)\n", ah.OperationCode)
	}
	fmt.Println("SenderMacAddr: ", ah.SenderMacAddr)
	fmt.Println("SenderIpAddr: ", ah.SenderIpAddr)
	fmt.Println("TargetMacAddr: ", ah.TargetMacAddr)
	fmt.Println("TargetIpAddr: ", ah.TargetIpAddr)
	fmt.Printf("PaddingData: %X\n", pd)
	fmt.Printf("-------------------------------\n")
}
