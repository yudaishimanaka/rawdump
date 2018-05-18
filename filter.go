package main

import (
	"time"

	"github.com/google/gopacket/pcap"
)

var (
	snapshot_len int32 = 1024
	promiscuous bool = true
	timeout	time.Duration = 30 * time.Second
)

func compileBPF(expr, ifname string) ([]pcap.BPFInstruction, error) {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		return nil, err
	}

	ifname = devices[0].Name

	handle, err := pcap.OpenLive(ifname, snapshot_len, promiscuous, timeout)
	if err != nil {
		return nil, err
	}
	defer handle.Close()

	var filter string = expr
	bpfRawInstructions, err := handle.CompileBPFFilter(filter)

	return bpfRawInstructions, nil
}
