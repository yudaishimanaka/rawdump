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

	if len(os.Args) != 2 {
		err := "device not found. please check machine interface."
		log.Fatal(err)
	}

	interfaceName := string(os.Args[1])

	interfaceIndex, err := net.InterfaceByName(interfaceName)
	if err != nil {
		log.Fatal(err)
	}

	addr := syscall.SockaddrLinklayer{Protocol:htons(syscall.ETH_P_ALL), Ifindex: interfaceIndex.Index}
	if err := syscall.Bind(fd, &addr); err != nil {
		log.Fatal(err)
	}

	if err := syscall.SetLsfPromisc(interfaceName, true); err != nil {
		log.Fatal(err)
	}

	file := os.NewFile(uintptr(fd), "")

	for {
		buffer := make([]byte, 1024)
		size := len(buffer)
		num, _ := file.Read(buffer)

		binaryData := buffer[:num]

		log.Printf("%X \n", binaryData)
	}
}
