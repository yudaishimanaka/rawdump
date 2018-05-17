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
#include <stdlib.h>
#include <stdint.h>
#include <libbpf/cbpf.h>
#include <libbpf/bpf_load.h>
#include <libbpf/ebpf.h>
#include <libbpf/pcap_helpers.h>
#include <libbpf/utils.h>
struct sock_fprog cbpf = {0};
*/
import "C"

import (
	"unsafe"
)

func SetBPF(expr, ifname string) error {
	ccbpf := *C.cbpf
	cexpr := C.CString(expr)
	cifname := C.CString(ifname)
	cbool := C.bool(0)
	defer C.free(unsafe.Pointer(cexpr))
	defer C.free(unsafe.Pointer(cifname))
	defer C.free(unsafe.Pointer(cbool))

	C.filter_try_compile(cexpr, ccbpf, C.dev_get_iftype(cifname))

	C.cbpf_dump_all(ccbpf, cbool)

	return nil
}
