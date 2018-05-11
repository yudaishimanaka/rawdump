package main

import (
	"bufio"
	"compress/gzip"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"time"
)

type Reader struct {
	r            io.Reader
	byteOrder    binary.ByteOrder
	nSecFactor   uint32
	versionMajor uint16
	versionMinor uint16
	snapLen      uint32
	linkType     uint8
	buf          [16]byte
}

const (
	magicNanosecounds           = 0xA1B23C4D
	magicMicrosecoundsBigendian = 0xD4C3B2A1
	magicNanosecoundsBigendian  = 0x4D3CB2A1
	magicGzip1                  = 0x1f
	magicGzip2                  = 0x8b
)

func NewReader(r io.Reader) (*Reader, error) {
	ret := Reader{r: r}
	if err := ret.readHeader(); err != nil {
		return nil, err
	}
	return &ret, nil
}

func (r *Reader) readHeader() error {
	bufRead := bufio.NewReader(r.r)
	gzipMazic, err := bufRead.Peek(2)
	if err != nil {
		return err
	}

	if gzipMazic[0] == magicGzip1 && gzipMazic[1] == magicGzip2 {
		if r.r, err = gzip.NewReader(bufRead); err != nil {
			return err
		}
	} else {
		r.r = bufRead
	}

	buf := make([]byte, 24)
	if n, err := io.ReadFull(r.r, buf); err != nil {
		return err
	} else if n < 24 {
		return errors.New("not enough data for read")
	}

	if magic := binary.LittleEndian.Uint32(buf[0:4]); magic == magicNanosecounds {
		r.byteOrder = binary.LittleEndian
		r.nSecFactor = 1
	} else if magic == magicNanosecoundsBigendian {
		r.byteOrder = binary.BigEndian
		r.nSecFactor = 1
	} else if magic == magicMicroseconds {
		r.byteOrder = binary.LittleEndian
		r.nSecFactor = 1000
	} else if magic == magicMicrosecoundsBigendian {
		r.byteOrder = binary.BigEndian
		r.nSecFactor = 1000
	} else {
		return fmt.Errorf("unknown magic %x", magic)
	}

	if r.versionMinor = r.byteOrder.Uint16(buf[4:6]); r.versionMinor != versionMajor {
		return fmt.Errorf("unknown major version %d", r.versionMajor)
	}

	if r.versionMinor = r.byteOrder.Uint16(buf[6:8]); r.versionMinor != versionMinor {
		return fmt.Errorf("unknown minor version %d", r.versionMinor)
	}

	r.snapLen = r.byteOrder.Uint32(buf[16:20])
	r.linkType = uint8(r.byteOrder.Uint32(buf[20:24]))

	return nil
}

func (r *Reader) readPacketHeader() (timeStamp time.Time, inclLen, origLen int, err error) {
	if _, err = io.ReadFull(r.r, r.buf[:]); err != nil {
		return
	}

	timeStamp = time.Unix(int64(r.byteOrder.Uint32(r.buf[0:4])), int64(r.byteOrder.Uint32(r.buf[4:8])*r.nSecFactor))
	inclLen = int(r.byteOrder.Uint32(r.buf[8:12]))
	origLen = int(r.byteOrder.Uint32(r.buf[12:16]))
	return
}

func (r *Reader) ReadPacketData() (data []byte, timeStamp time.Time, inclLen, origLen int, err error) {
	if timeStamp, inclLen, origLen, err = r.readPacketHeader(); err != nil {
		return
	}

	if inclLen > int(r.snapLen) {
		err = fmt.Errorf("capture length exceeds snap length")
		return
	}

	data = make([]byte, inclLen)
	_, err = io.ReadFull(r.r, data)
	return data, timeStamp, inclLen, origLen, err
}
