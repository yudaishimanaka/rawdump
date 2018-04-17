package main

import (
	"log"
	"net"
	"os"
	"syscall"
)

const (
	exitCodeOk = iota
	exitCodeErr
)

func htons(host uint16) uint16 {
	return (host&0xff)<<8 | (host >> 8)
}

func main() {
	// get raw sock
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(syscall.ETH_P_ALL)))
	if err != nil {
		log.Fatal(err)
	}

	// defer close fd
	defer syscall.Close(fd)

	// argument check
	if len(os.Args) != 2 {
		err := "device not found. please check machine interface."
		log.Fatal(err)
	}

	// get interface name from argument
	interfaceName := string(os.Args[1])

	// check interface exist
	interfaceIndex, err := net.InterfaceByName(interfaceName)
	if err != nil {
		log.Fatal(err)
	}

	// bind interface
	addr := syscall.SockaddrLinklayer{Protocol: htons(syscall.ETH_P_ALL), Ifindex: interfaceIndex.Index}
	if err := syscall.Bind(fd, &addr); err != nil {
		log.Fatal(err)
	}

	// set promiscuous flag
	if err := syscall.SetLsfPromisc(interfaceName, true); err != nil {
		log.Fatal(err)
	}

	file := os.NewFile(uintptr(fd), "")

	// loop analyze raw packet
	for {
		buffer := make([]byte, 4096)
		num, err := file.Read(buffer)
		if err != nil {
			log.Fatal(err)
			break
		} else {
			binaryData := buffer[:num]

			err := analyzePacket(binaryData, num)
			if err != nil {
				log.Fatal(err)
				break
			}
		}
	}

	// exit
	os.Exit(exitCodeOk)
}
