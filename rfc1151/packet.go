package rfc1151

import (
	"encoding/binary"
	"fmt"
	"hash/crc32"

	"github.com/CrimeanBitches/go-flags"
)

const (
	// Packet flags
	// SYN is ...
	SYN flags.Byte = 1
	// ACK is ...
	ACK flags.Byte = 1 << 1
	// EAK is ...
	EAK flags.Byte = 1 << 2
	// RST is ...
	RST flags.Byte = 1 << 3
	// NUL is ...
	NUL flags.Byte = 1 << 4

	// V1 is ...
	VERSION flags.Byte = 1 << 7

	// Options flags
	// SMD is ...
	SMD flags.Uint16 = 1
	// todo other flags
)

type Packet struct {
	// fields are ordered to take less memory
	flags       flags.Byte
	sourcePort  uint16
	destPort    uint16
	sequenceNum uint32
	ackNum      uint32
	checksum    uint32
	eak         []uint32
	data        []byte
	options     []uint16
}

func (p *Packet) Version() byte {
	return byte(VERSION)
}

func (p *Packet) Flags() flags.Byte {
	return p.flags
}

func (p *Packet) SourcePort() uint16 {
	return p.sourcePort
}

func (p *Packet) DestPort() uint16 {
	return p.destPort
}

func (p *Packet) SequenceNum() uint32 {
	return p.sequenceNum
}

func (p *Packet) AckNum() uint32 {
	return p.ackNum
}

func (p *Packet) Checksum() uint32 {
	return p.checksum
}

func (p *Packet) Eak() []uint32 {
	return p.eak
}

func (p *Packet) Data() []byte {
	return p.data
}

func (p *Packet) Options() []uint16 {
	return p.options
}

func (p *Packet) fromBytes(b []byte) error {
	end := binary.LittleEndian

	index := 0

	p.flags = flags.Byte(b[index]) // read flags 1b
	index++

	hLen := int(b[index]) // header len 1b
	index++

	p.sourcePort = end.Uint16(b[index : index+2]) // src port 2b
	index += 2

	p.destPort = end.Uint16(b[index : index+2]) // dst port 2b
	index += 2

	dLen := int(end.Uint16(b[index : index+2])) // data len 2b
	index += 2

	p.sequenceNum = end.Uint32(b[index : index+4]) // seq num 4b
	index += 4

	p.ackNum = end.Uint32(b[index : index+4]) // ack num 4b
	index += 4

	p.checksum = end.Uint32(b[index : index+4]) // checksum 4b
	index += 4

	if p.flags.IsAny(EAK) {
		l := int((hLen - 20) / 4)
		p.eak = make([]uint32, l)
		for i := 0; i < l; i++ {
			p.eak[i] = end.Uint32(b[index : index+4])
			index += 4
		}
	}

	// data dLen b
	if dLen > 0 {
		p.data = make([]byte, dLen)
		copy(p.data, b[index:index+dLen])
		index += dLen
	}

	// options len - (hLen + dLen)
	if p.flags.IsAny(SYN) {
		l := (len(b) - hLen - dLen) / 2
		p.options = make([]uint16, l)
		for i := 0; i < l; i++ {
			p.options[i] = end.Uint16(b[index : index+2])
			index += 2
		}
	}

	// todo handle errors
	return nil
}

func (p *Packet) toBytes(buffer []byte) ([]byte, error) {
	l := 0
	// constant header size
	hLen := 20
	// eak size
	if p.flags.IsAny(EAK) {
		hLen += len(p.eak) * 4
	}
	l += hLen

	dLen := len(p.data)
	l += dLen

	optsLen := 0
	if p.options != nil {
		optsLen = len(p.options)
		l += optsLen * 2
	}

	if len(buffer) < l {
		return nil, fmt.Errorf("buffer size less that composing packet size")
	}

	end := binary.LittleEndian
	index := 0

	buffer[index] = byte(p.flags)
	index++

	buffer[index] = byte(hLen)
	index++

	end.PutUint16(buffer[index:index+2], p.sourcePort)
	index += 2

	end.PutUint16(buffer[index:index+2], p.destPort)
	index += 2

	end.PutUint16(buffer[index:index+2], uint16(dLen))
	index += 2

	end.PutUint32(buffer[index:index+4], p.sequenceNum)
	index += 4

	end.PutUint32(buffer[index:index+4], p.ackNum)
	index += 4

	end.PutUint32(buffer[index:index+4], uint32(0))
	index += 4

	if p.flags.IsAny(EAK) {
		eakLen := len(p.eak)
		for i := 0; i < eakLen; i++ {
			end.PutUint32(buffer[index:index+4], p.eak[i])
			index += 4
		}
	}

	if dLen > 0 {
		copy(buffer[index:index+dLen], p.data)
		index += dLen
	}

	if optsLen > 0 {
		for i := 0; i < optsLen; i++ {
			end.PutUint16(buffer[index:index+2], p.options[i])
			index += 2
		}
	}

	p.checksum = crc32.ChecksumIEEE(buffer[:l])
	binary.LittleEndian.PutUint32(buffer[16:20], p.checksum)

	// todo handle errors
	return buffer[:l], nil
}
