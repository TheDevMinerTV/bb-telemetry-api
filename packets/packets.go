package packets

import (
	"encoding/binary"
	"fmt"
	"io"
)

/*
 * Packet structure:
 * 4 bytes: packet data length, describes the length of the packet data (the last section)
 * 1 byte: packet type
 * n bytes: packet data
 */

type PacketType byte

const (
	HandshakeRequestPacket  PacketType = 1
	HandshakeResponsePacket PacketType = 2
	StartRequestPacket      PacketType = 3
	StartResponsePacket     PacketType = 4
	HeartbeatRequestPacket  PacketType = 5
	HeartbeatResponsePacket PacketType = 6

	// DataLengthSize describes how long the payload length is in bytes
	DataLengthSize = 2
	// PacketTypeLength describes how long the packet type is in bytes
	PacketTypeLength = 1
)

func ReadLength(buf []byte) int {
	return int(binary.BigEndian.Uint16(buf[:DataLengthSize]))
}

type Packet interface {
	Type() PacketType
	Encode() []byte
}

func Parse(raw []byte) (p *Wrapped, err error) {
	if len(raw) < 1 {
		return nil, fmt.Errorf("packet too short: %d", len(raw))
	}

	p = &Wrapped{}

	typ := PacketType(raw[0])
	raw = raw[PacketTypeLength:]

	switch typ {
	case HandshakeRequestPacket:
		p.Inner, err = DecodeHandshakeRequest(raw)

	case HandshakeResponsePacket:
		p.Inner, err = DecodeHandshakeResponse(raw)

	case StartRequestPacket:
		p.Inner, err = DecodeStartRequest(raw)

	case StartResponsePacket:
		p.Inner, err = DecodeStartResponse()

	case HeartbeatRequestPacket:

	default:
		err = fmt.Errorf("unknown packet type: %d", typ)
	}
	if err != nil {
		return nil, err
	}

	return p, nil
}

type Wrapped struct {
	Inner Packet
}

func NewWrapped(inner Packet) *Wrapped {
	return &Wrapped{Inner: inner}
}

func (p *Wrapped) Encode() []byte {
	inner := p.Inner.Encode()

	dataLength := len(inner)
	length := DataLengthSize + PacketTypeLength + dataLength

	buf := make([]byte, length)

	binary.BigEndian.PutUint16(buf[0:], uint16(dataLength))
	buf[DataLengthSize] = byte(p.Inner.Type())
	copy(buf[DataLengthSize+PacketTypeLength:], inner)

	return buf
}

func encodedStringLength(s string) int {
	return 2 + len(s)
}

func writeString(buf []byte, offset int, s string) int {
	strLen := len(s)

	binary.BigEndian.PutUint16(buf[offset:], uint16(strLen))
	offset += 2

	copy(buf[offset:], s)
	offset += strLen

	return offset
}

func readString(buf []byte, offset int) (string, int, error) {
	if len(buf) < offset+2 {
		return "", 0, io.ErrUnexpectedEOF
	}

	strLen := int(binary.BigEndian.Uint16(buf[offset:]))
	offset += 2

	if len(buf) < offset+strLen {
		return "", 0, io.ErrUnexpectedEOF
	}

	return string(buf[offset : offset+strLen]), offset + strLen, nil
}
