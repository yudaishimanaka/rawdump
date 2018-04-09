package main

import (
	"log"
	"os"
	"syscall"
	"net"
)

func htons(host uint16) uint16 {
	return (host&0xff)<<8 | (host >> 8)
}

func main() {
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(syscall.ETH_P_ALL)))
	if err != nil {
		log.Fatal(err)
	}

	defer syscall.Close(fd)

	interfaceIndex, err := net.InterfaceByName("wlp3s0")
	if err != nil {
		log.Fatal(err)
	}

	addr := syscall.SockaddrLinklayer{Protocol:htons(syscall.ETH_P_ALL), Ifindex: interfaceIndex.Index}
	if err := syscall.Bind(fd, &addr); err != nil {
		log.Fatal(err)
	}

	if err := syscall.SetLsfPromisc("wlp3s0", true); err != nil {
		log.Fatal(err)
	}

	file := os.NewFile(uintptr(fd), "")

	for {
		buffer := make([]byte, 1024)
		num, _ := file.Read(buffer)

		log.Printf("% X\n", buffer[:num])
	}
}
