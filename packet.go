package rdp

import flags "github.com/CrimeanBitches/go-flags"

// RFC ABSTRACTED PACKET
type Packet interface {
	Version() byte
	Flags() flags.Byte
	SourcePort() uint16
	DestPort() uint16
	SequenceNum() uint32
	AckNum() uint32
	Checksum() uint32
	Eak() []uint32
	Data() []byte
	Options() []uint16

	fromBytes(b []byte) error
	toBytes() ([]byte, error)
}
