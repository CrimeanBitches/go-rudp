package rfc908

import (
	"math/rand"
	"strconv"
	"testing"
)

var buffer = make([]byte, 1024+128)

func Benchmark10kkToBytes(t *testing.B) {
	data := []byte(RandStringRunes(1024))
	p := &Packet{
		flags:       VERSION.Add(SYN, ACK, EAK),
		sequenceNum: 12345678,
		ackNum:      12345677,
		sourcePort:  128,
		destPort:    127,
		eak:         []uint32{123217389, 1382173892, 12372138, 12732173},
		data:        data,
		options:     []uint16{32, 128, 32000},
	}

	i := 10000000
	for i > 0 {
		p.toBytes(buffer)
		i--
	}
}

func test(p1 *Packet, p2 *Packet, t *testing.T) {
	t.Logf("flags - %v : %v", p1.flags, p2.flags)
	if p1.flags != p2.flags {
		t.FailNow()
	}

	t.Logf("sourcePort - %v : %v", p1.sourcePort, p2.sourcePort)
	if p1.sourcePort != p2.sourcePort {
		t.FailNow()
	}

	t.Logf("destPort - %v : %v", p1.destPort, p2.destPort)
	if p1.destPort != p2.destPort {
		t.FailNow()
	}

	t.Logf("sequenceNum - %v : %v", p1.sequenceNum, p2.sequenceNum)
	if p1.sequenceNum != p2.sequenceNum {
		t.FailNow()
	}

	t.Logf("ackNum - %v : %v", p1.ackNum, p2.ackNum)
	if p1.ackNum != p2.ackNum {
		t.FailNow()
	}

	t.Logf("checksum - %v : %v", p1.checksum, p2.checksum)
	if p1.checksum != p2.checksum {
		t.FailNow()
	}

	t.Logf("eak len - %v : %v", len(p1.eak), len(p2.eak))
	if len(p1.eak) != len(p2.eak) {
		t.FailNow()
	}

	for i := 0; i < len(p1.eak); i++ {
		t.Logf("eak [%v] - %v : %v", strconv.Itoa(i), p1.eak[i], p2.eak[i])
		if p1.eak[i] != p2.eak[i] {
			t.FailNow()
		}
	}

	t.Logf("data len - %v : %v", len(p1.data), len(p2.data))
	if len(p1.data) != len(p2.data) {
		t.FailNow()
	}

	t.Logf("data - %v : %v", string(p1.data), string(p2.data))
	if string(p1.data) != string(p2.data) {
		t.FailNow()
	}

	t.Logf("options len - %v : %v", len(p1.options), len(p2.options))
	if len(p1.options) != len(p2.options) {
		t.FailNow()
	}

	for i := 0; i < len(p1.options); i++ {
		t.Logf("options [%v] - %v : %v", strconv.Itoa(i), p1.options[i], p2.options[i])
		if p1.options[i] != p2.options[i] {
			t.FailNow()
		}
	}
}

func Benchmark10kkFromBytes(t *testing.B) {
	data := []byte(RandStringRunes(1024))
	p := &Packet{
		flags:       VERSION.Add(SYN, ACK, EAK),
		sequenceNum: 12345678,
		ackNum:      12345677,
		sourcePort:  128,
		destPort:    127,
		eak:         []uint32{123217389, 1382173892, 12372138, 12732173},
		data:        data,
		options:     []uint16{32, 128, 32000},
	}
	bytes, _ := p.toBytes(buffer)

	i := 10000000
	for i > 0 {
		p.fromBytes(bytes)
		i--
	}
}

func TestPacketSYN(t *testing.T) {
	p1 := &Packet{
		flags:       VERSION.Add(SYN),
		sequenceNum: 12345678,
		ackNum:      12345677,
		sourcePort:  128,
		destPort:    127,
		options:     []uint16{32, 128, 32000},
	}

	b, err := p1.toBytes(buffer)
	if err != nil {
		t.Error(err)
	}
	p2 := &Packet{}
	err = p2.fromBytes(b)
	if err != nil {
		t.Error(err)
	}

	test(p1, p2, t)
}

func TestPacketACK(t *testing.T) {
	data := []byte("some data")
	p1 := &Packet{
		flags:       VERSION.Add(ACK),
		sequenceNum: 12345678,
		ackNum:      12345677,
		sourcePort:  128,
		destPort:    127,
		data:        data,
	}

	b, _ := p1.toBytes(buffer)
	p2 := &Packet{}
	err := p2.fromBytes(b)
	if err != nil {
		t.Error(err)
	}

	test(p1, p2, t)
}

func TestPacketSYN_ACK(t *testing.T) {
	data := []byte("some data")
	p1 := &Packet{
		flags:       VERSION.Add(SYN, ACK),
		sequenceNum: 12345678,
		ackNum:      12345677,
		sourcePort:  128,
		destPort:    127,
		data:        data,
		options:     []uint16{32, 128, 32000},
	}

	b, _ := p1.toBytes(buffer)
	p2 := &Packet{}
	err := p2.fromBytes(b)
	if err != nil {
		t.Error(err)
	}

	test(p1, p2, t)
}
func TestPacketACK_EAK(t *testing.T) {
	data := []byte("some data")
	p1 := &Packet{
		flags:       VERSION.Add(ACK, EAK),
		sequenceNum: 12345678,
		ackNum:      12345677,
		sourcePort:  128,
		destPort:    127,
		eak:         []uint32{123217389, 1382173892, 12372138, 12732173},
		data:        data,
	}

	b, _ := p1.toBytes(buffer)
	p2 := &Packet{}
	err := p2.fromBytes(b)
	if err != nil {
		t.Error(err)
	}

	test(p1, p2, t)
}

func TestPacketRST(t *testing.T) {
	p1 := &Packet{
		flags:       VERSION.Add(RST),
		sequenceNum: 12345678,
		ackNum:      12345677,
		sourcePort:  128,
		destPort:    127,
	}

	b, _ := p1.toBytes(buffer)
	p2 := &Packet{}
	err := p2.fromBytes(b)
	if err != nil {
		t.Error(err)
	}

	test(p1, p2, t)
}

var letterRunes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

func RandStringRunes(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = letterRunes[rand.Intn(len(letterRunes))]
	}
	return string(b)
}
