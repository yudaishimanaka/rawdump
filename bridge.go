package main

import (
	"log"
	"golang.org/x/sys/unix"
	"os"
)

type Dev struct {
	soc	int32
}

var device [2]Dev

func Bridge(device0, device1 Dev) error {
	var nReady, i, size int
	var err error
	var target1, target2 unix.PollFd
	var targets []unix.PollFd
	var devices [2]Dev
	devices[0] = device0
	devices[1] = device1
	buffer := make([]byte, 4096)

	target1.Fd = devices[0].soc
	target1.Events = unix.POLLIN|unix.POLLERR
	target2.Fd = device[1].soc
	target2.Events = unix.POLLIN|unix.POLLERR

	targets = append(targets, target1)
	targets = append(targets, target2)

	for {
		nReady, err = unix.Poll(targets, 100)
		if err != nil {
			return err
		}

		switch nReady{
		case -1:
			log.Println("poll")
			break

		case 0:
			break

		default:
			for i = 0; i < 2; i++ {
				if targets[i].Revents&(unix.POLLIN|unix.POLLERR) == 0 {
					if size, err = unix.Read(int(devices[i].soc), buffer); size <= 0 {
						log.Printf("Read Error\n")
					}
				} else {
					log.Println(size)
					if err := analyzePacket(buffer, size); err != nil {
						log.Fatal(err)
					} else {
						if size, err = unix.Read(int(devices[^i].soc), buffer); size <= 0 {
							log.Printf("Write Error\n")
						}
					}
				}
			}
			break
		}
	}
	return nil
}

func DisableIpForward() error {
	file, err := os.Open("/proc/sys/net/ipv4/ip_forward")
	if err != nil {
		return err
	}
	defer file.Close()

	output := "0"
	file.Write(([]byte)(output))
	return nil
}