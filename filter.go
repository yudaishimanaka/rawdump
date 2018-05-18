package main

import (
	"time"

	"github.com/google/gopacket/pcap"
	"syscall"
	"unsafe"
)

var (
	snapshot_len int32         = 65536
	promiscuous  bool          = true
	timeout      time.Duration = 30 * time.Second
)

func CompileBPF(expr, ifname string) ([]pcap.BPFInstruction, error) {
	// find device
	devices, err := pcap.FindAllDevs()
	if err != nil {
		return nil, err
	}

	ifname = devices[0].Name

	// handle libpcap
	handle, err := pcap.OpenLive(ifname, snapshot_len, promiscuous, timeout)
	if err != nil {
		return nil, err
	}
	defer handle.Close()

	// compile filter string
	var filter string = expr
	bpfRawInstructions, err := handle.CompileBPFFilter(filter)

	return bpfRawInstructions, nil
}

func SetBPF(fd int, filter []pcap.BPFInstruction) error {
	// create bpf program
	prog := syscall.SockFprog{
		Len:    uint16(len(filter)),
		Filter: (*syscall.SockFilter)(unsafe.Pointer(&filter[0])),
	}

	// set socket option
	_, _, err := syscall.Syscall6(syscall.SYS_SETSOCKOPT, uintptr(fd), uintptr(syscall.SOL_SOCKET), uintptr(syscall.SO_ATTACH_FILTER), uintptr(unsafe.Pointer(&prog)), uintptr(uint32(unsafe.Sizeof(prog))), 0)
	if err != 0 {
		return err
	}
	return nil
}
