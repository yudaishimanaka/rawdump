package main

import (
	"log"
	"golang.org/x/sys/unix"
	"os"
)

type Param struct {
	Device1	 string
	Device2  string
	DebugOut int
}

type Dev struct {
	soc	int32
}

func Bridge() error {
	var nReady, i, size int
	var err error
	var targets []unix.PollFd
	var device [2]Dev
	// buffer := make([]byte, 4096)
	// var param = Param{"wlp3s0", "enp0s25", 1}

	targets[0].Fd = device[0].soc
	targets[0].Events = unix.POLLIN|unix.POLLERR
	targets[1].Fd = device[1].soc
	targets[1].Events = unix.POLLIN|unix.POLLERR

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
					log.Println("read")
				} else {
					// size variable use block
					log.Println(size)
				}
			}
			break
		}
	}
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