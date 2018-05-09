package main

import (
	"encoding/binary"
	"io"
	"log"
	"time"
)

type Writer struct {
	w io.Writer

	// The size of PcapFileHeader and PcapPacketHeader are substantially the same size.
	// http://wiki.wireshark.org/Development/LibpcapFileFormat
	buf [16]byte
}

const (
	magicMicroseconds = 0xA1B2C3D4
	versionMajor      = 2
	versionMinor      = 4
	nanosPerMicro     = 1000
)

func newWriter(w io.Writer) *Writer {
	return &Writer{w: w}
}

func (w *Writer) writeFileHeader(snaplen uint32, linktype uint8) error {
	var buf [24]byte
	binary.LittleEndian.PutUint32(buf[0:4], magicMicroseconds)
	binary.LittleEndian.PutUint16(buf[4:6], versionMajor)
	binary.LittleEndian.PutUint16(buf[6:8], versionMinor)
	binary.LittleEndian.PutUint32(buf[16:20], snaplen)
	binary.LittleEndian.PutUint32(buf[20:24], uint32(linktype))
	_, err := w.w.Write(buf[:])
	return err
}

func (w *Writer) writePacketHeader(inclLen, origLen int) error {
	t := time.Now()
	secs := t.Unix()
	usecs := t.Nanosecond() / nanosPerMicro
	binary.LittleEndian.PutUint32(w.buf[0:4], uint32(secs))
	binary.LittleEndian.PutUint32(w.buf[4:8], uint32(usecs))
	binary.LittleEndian.PutUint32(w.buf[8:12], uint32(inclLen))
	binary.LittleEndian.PutUint32(w.buf[12:16], uint32(origLen))
	_, err := w.w.Write(w.buf[:])
	return err
}

func (w *Writer) writePacket(incLen, origLen int, data []byte) error {
	if incLen != len(data) {
		log.Fatal("capture length does not match data length")
	}

	if incLen > origLen {
		log.Fatal("invalid capture info. incLen > origLen")
	}

	if err := w.writePacketHeader(incLen, origLen); err != nil {
		log.Fatal(err)
	}

	_, err := w.w.Write(data)
	return err
}
