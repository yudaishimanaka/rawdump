package main

import (
	"flag"
	"log"
	"net"
	"os"
	"syscall"
	"regexp"
)

const (
	exitCodeOk = iota
	exitCodeErr

	regexString = `^([a-zA-Z0-9]*)\sto\s([a-zA-Z0-9]*)$`
)

func htons(host uint16) uint16 {
	return (host&0xff)<<8 | (host >> 8)
}


var r = regexp.MustCompile(regexString)

func parseBridgeString(expr string) []string {
	var array []string
	for i := range r.FindStringSubmatch(expr) {
		result := r.FindStringSubmatch(expr)[i]
		array = append(array, result)
	}
	return array
}

func main() {
	// get raw sock
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(syscall.ETH_P_ALL)))
	if err != nil {
		log.Fatal(err)
	}

	// defer close fd
	defer syscall.Close(fd)

	// get flag
	var (
		d = flag.String("d", "", "-d [device]: device(network interface)")
		w = flag.String("w", "none", "-w [filename]: data write pcap file")
		r = flag.String("r", "none", "-r [filename]: read pcap file")
		f = flag.String("f", "none", "-f \"[filter]\": filter(e.g. \"tcp and port 12345\")")
		b = flag.String("b", "none", "-b \"[src_interface] to [dst_interface]\": run bridge mode")
	)

	flag.Parse()

	// flag management
	var dFlag, wFlag, rFlag, fFlag, bFlag bool

	if *d != "" {
		dFlag = true
	}

	if *w != "none" {
		wFlag = true
	}

	if *r != "none" {
		rFlag = true
	}

	if *f != "none" {
		fFlag = true
	}

	if *b != "none" {
		bFlag = true
	}

	if bFlag == true {
		// fwdInterface fd or soc
		fd2, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(syscall.ETH_P_ALL)))
		if err != nil {
			log.Fatal(err)
		}

		// get forward interface
		result := parseBridgeString(*b)

		// check interface and get interfaceIndex
		interfaceIndex1, err := net.InterfaceByName(result[1])
		if err != nil {
			log.Fatal(err)
		}

		interfaceIndex2, err := net.InterfaceByName(result[2])
		if err != nil {
			log.Fatal(err)
		}

		// bind interface
		addr1 := syscall.SockaddrLinklayer{Protocol: htons(syscall.ETH_P_ALL), Ifindex: interfaceIndex1.Index}
		if err := syscall.Bind(fd, &addr1); err != nil {
			log.Fatal(err)
		}

		addr2 := syscall.SockaddrLinklayer{Protocol: htons(syscall.ETH_P_ALL), Ifindex: interfaceIndex2.Index}
		if err := syscall.Bind(fd2, &addr2); err != nil {
			log.Fatal(err)
		}

		device[0].soc = int32(fd)
		device[1].soc = int32(fd2)

		DisableIpForward()

		Bridge(device[0], device[1])
	}

	// check the dFlag before initializing the raw socket
	if dFlag == false {
		if rFlag == true {
			if fFlag == true {
				data, err := CompileBPF(*f, *d)
				if err != nil {
					log.Fatal(err)
				}

				err = SetBPF(fd, data)
				if err != nil {
					log.Fatal(err)
				}

				f, _ := os.Open(*r)
				defer f.Close()
				r, err := NewReader(f)
				if err != nil {
					log.Fatal(err)
				}
				for {
					data, _, _, _, err := r.ReadPacketData()
					if err != nil {
						log.Fatal(err)
						break
					}

					if err := analyzePacket(data, len(data)); err != nil {
						log.Fatal(err)
						break
					}
				}
			} else {
				f, _ := os.Open(*r)
				defer f.Close()
				r, err := NewReader(f)
				if err != nil {
					log.Fatal(err)
				}
				for {
					data, _, _, _, err := r.ReadPacketData()
					if err != nil {
						log.Fatal(err)
						break
					}

					if err := analyzePacket(data, len(data)); err != nil {
						log.Fatal(err)
						break
					}
				}
			}
		} else {
			log.Fatal("please select device or put read option")
		}
	}

	// get interface name from flag
	interfaceName := *d

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

	// check flag and processing
	if dFlag == true {
		if wFlag == true && fFlag == true {
			data, err := CompileBPF(*f, *d)
			if err != nil {
				log.Fatal(err)
			}

			err = SetBPF(fd, data)
			if err != nil {
				log.Fatal(err)
			}

			f, _ := os.Create(*w)
			writer := NewWriter(f)
			writer.WriteFileHeader(65536, LinkTypeEthernet)
			f.Close()
			for {
				f, _ := os.OpenFile(*w, os.O_APPEND|os.O_WRONLY, 0700)
				writer := NewWriter(f)
				// buffer size is 4096 ~ 65535, AWS spew errors even at 4096 byes
				buffer := make([]byte, 4096)
				num, err := file.Read(buffer)
				if err != nil {
					log.Fatal(err)
					break
				} else {
					binaryData := buffer[:num]

					writer.WritePacket(num, num, binaryData)
					f.Close()
					err := analyzePacket(binaryData, num)
					if err != nil {
						log.Fatal(err)
						break
					}
				}
			}
		} else if wFlag == true && fFlag == false {
			f, _ := os.Create(*w)
			writer := NewWriter(f)
			writer.WriteFileHeader(65536, LinkTypeEthernet)
			f.Close()
			for {
				f, _ := os.OpenFile(*w, os.O_APPEND|os.O_WRONLY, 0700)
				writer := NewWriter(f)
				// buffer size is 4096 ~ 65535, AWS spew errors even at 4096 byes
				buffer := make([]byte, 4096)
				num, err := file.Read(buffer)
				if err != nil {
					log.Fatal(err)
					break
				} else {
					binaryData := buffer[:num]

					writer.WritePacket(num, num, binaryData)
					f.Close()
					err := analyzePacket(binaryData, num)
					if err != nil {
						log.Fatal(err)
						break
					}
				}
			}
		} else if wFlag == false && fFlag == true {
			data, err := CompileBPF(*f, *d)
			if err != nil {
				log.Fatal(err)
			}

			err = SetBPF(fd, data)
			if err != nil {
				log.Fatal(err)
			}

			for {
				// buffer size is 4096 ~ 65535, AWS spew errors even at 4096 byes
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
		} else {
			for {
				// buffer size is 4096 ~ 65535, AWS spew errors even at 4096 byes
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
		}
	}

	// exit
	os.Exit(exitCodeOk)
}
