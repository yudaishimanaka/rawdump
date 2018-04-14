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
	fmt.Printf("--------------Arp--------------\n")
	fmt.Printf("HardwareType: %X\n", ah.HardwareType)
	fmt.Printf("ProtoType: %X\n", ah.ProtoType)
	fmt.Printf("MacAddrLen: %X\n", ah.MacAddrLen)
	fmt.Printf("IpAddrLen: %X\n", ah.IpAddrLen)
	fmt.Printf("OperationCode: %X\n", ah.OperationCode)
	fmt.Println("SenderMacAddr: ", ah.SenderMacAddr)
	fmt.Println("SenderIpAddr: ", ah.SenderIpAddr)
	fmt.Println("TargetMacAddr: ", ah.TargetMacAddr)
	fmt.Println("TargetIpAddr: ", ah.TargetIpAddr)
	fmt.Printf("PaddingData: %X\n", pd)
	fmt.Printf("-------------------------------\n")
}
