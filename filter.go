/*
	compliance of BPF
*/

package main

/*
#cgo solaris LDFLAGS: -L /opt/local/lib -lpcap
#cgo linux LDFLAGS: -lpcap
#cgo dragonfly LDFLAGS: -lpcap
#cgo freebsd LDFLAGS: -lpcap
#cgo openbsd LDFLAGS: -lpcap
#cgo netbsd LDFLAGS: -lpcap
#cgo darwin LDFLAGS: -lpcap
#cgo windows CFLAGS: -I C:/WpdPack/Include
#cgo windows,386 LDFLAGS: -L C:/WpdPack/Lib -lwpcap
#cgo windows,amd64 LDFLAGS: -L C:/WpdPack/Lib/x64 -lwpcap
#include "libbpf/cbpf.h"
#include "libbpf/bpf_load.h"
#include "libbpf/ebpf.h"
#include "libbpf/pcap_helpers.h"
#include "libbpf/utils.h"
*/
import "C"
