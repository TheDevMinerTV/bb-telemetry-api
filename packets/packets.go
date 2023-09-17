package packets

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
)

type PacketType byte

const (
	HandshakeRequestPacket  PacketType = 0x01
	HandshakeResponsePacket PacketType = 0x02
	StartRequestPacket      PacketType = 0x03
	StartResponsePacket     PacketType = 0x04
	HeartbeatRequestPacket  PacketType = 0x05
	HeartbeatResponsePacket PacketType = 0x06
)

type Packet interface {
	Type() PacketType
	Encode() []byte
}

func Parse(raw []byte) (*Wrapped, error) {
	if len(raw) < 1 {
		return nil, io.ErrUnexpectedEOF
	}

	p := &Wrapped{}

	typ := PacketType(raw[0])
	var err error = nil
	switch typ {
	case HandshakeRequestPacket:
		p.Inner, err = DecodeHandshakeRequest(raw[1:])

	case StartRequestPacket:
		p.Inner, err = DecodeStartRequest(raw[1:])

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

	length := 1 + len(inner)
	log.Printf("length: %d", length)

	buf := make([]byte, 2+length)

	binary.BigEndian.PutUint16(buf[0:], uint16(length))

	buf[2] = byte(p.Inner.Type())
	copy(buf[2+1:], inner)

	return buf
}
