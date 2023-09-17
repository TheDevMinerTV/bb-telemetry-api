package packets

import (
	"encoding/binary"
	"io"
)

type HandshakeRequest struct {
	Module  string
	Version string
}

func (p *HandshakeRequest) Type() PacketType {
	return HandshakeRequestPacket
}

func (p *HandshakeRequest) Encode() []byte {
	moduleLen := len(p.Module)
	versionLen := len(p.Version)

	buf := make([]byte, 2+len(p.Module)+2+len(p.Version))
	offset := 0

	binary.BigEndian.PutUint16(buf[0:], uint16(moduleLen))
	offset += 2
	copy(buf[2:], p.Module)
	offset += moduleLen

	binary.BigEndian.PutUint16(buf[offset:], uint16(versionLen))
	offset += 2
	copy(buf[offset:], p.Version)

	return buf
}

func DecodeHandshakeRequest(raw []byte) (*HandshakeRequest, error) {
	if len(raw) < 2 {
		return nil, io.ErrUnexpectedEOF
	}
	moduleLength := binary.BigEndian.Uint16(raw[:2])
	raw = raw[2:]

	if len(raw) < int(moduleLength) {
		return nil, io.ErrUnexpectedEOF
	}
	module := string(raw[:moduleLength])
	raw = raw[moduleLength:]
	if len(raw) < 2 {
		return nil, io.ErrUnexpectedEOF
	}

	versionLength := binary.BigEndian.Uint16(raw[:2])
	raw = raw[2:]
	if len(raw) < int(versionLength) {
		return nil, io.ErrUnexpectedEOF
	}

	version := string(raw[:versionLength])

	return &HandshakeRequest{
		Module:  module,
		Version: version,
	}, nil
}

type HandshakeResponse struct {
	Key [32]byte
}

func NewHandshakeResponse(key [32]byte) *HandshakeResponse {
	return &HandshakeResponse{Key: key}
}

func (p *HandshakeResponse) Type() PacketType {
	return HandshakeResponsePacket
}

func (p *HandshakeResponse) Encode() []byte {
	buf := make([]byte, 32)

	copy(buf[0:], p.Key[:])

	return buf
}

func DecodeHandshakeResponse(raw []byte) (*HandshakeResponse, error) {
	if len(raw) < 32 {
		return nil, io.ErrUnexpectedEOF
	}

	var key [32]byte
	copy(key[:], raw[:32])

	return &HandshakeResponse{Key: key}, nil
}
