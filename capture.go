package main

import (
	"log"
	"net"
	"syscall"
)

func main() {
	// fd
	const proto = (syscall.ETH_P_ALL<<8)&0xff00 | syscall.ETH_P_ALL>>8

	// Make buffer
	buffer := make([]byte, 4*1024)

	// Create socket
	sock, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, proto)
	if err != nil {
		log.Println(err)
	}
	// Defer close socket
	defer syscall.Close(sock)

	// Get interfaceIndex
	interfaceIndex, err := net.InterfaceByName("wlp3s0")
	if err != nil {
		log.Println(err)
	}

	// Get link_layer_addr and bind interface
	addr := syscall.SockaddrLinklayer{Protocol: proto, Ifindex: interfaceIndex.Index}
	if err := syscall.Bind(sock, &addr); err != nil {
		log.Println(err)
	}

	// Set promisc
	if err := syscall.SetLsfPromisc("wlp3s0", true); err != nil {
		log.Println(err)
	}

	// Receive data
	for {
		data, peer, err := syscall.Recvfrom(sock, buffer, 0)
		if err != nil {
			log.Println(err)
		}
		log.Println(data, peer)
	}

}
