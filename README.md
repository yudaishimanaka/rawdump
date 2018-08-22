# rawdump
Simple raw socket packet capture.

## Demo
![demo](https://github.com/yudaishimanaka/rawdump/blob/master/rawdump-demo.gif)

## Requirement
- Golang 1.10 ~
- External package
  - golang.org/x/sys/unix
  - github.com/google/gopacket/pcap

## Install
`make`

## Usage
First, Let's move the binary(`rawdump`) to `/usr/bin/`

### Capture
e.g.) `sudo rawdump -d eth0 -f "tcp and port 80"`

### Options
*`-d`* : Selecting a network interface. Interface name after option.  
*`-f`* : Filtering based on `tcpdump`. Filter string enclosed in double quotes after option.  
*`-w`* : Write the results of the capture to the pcap file. File name after option.  
*`-r`* : Read pcap file. File name after option.  
*`-b`* : Bridge capture mode. e.g.) `sudo rawdump -b "eht0 to eth1"`  

## License
The MIT License (MIT) -see `LICENSE` for more details.  
