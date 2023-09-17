package packets

import (
	"encoding/binary"
	"io"
	"log"
)

type ModuleInfo struct {
	Module  string
	Version string
}

func (m *ModuleInfo) EncodedLen() int {
	return encodedStringLength(m.Module) + encodedStringLength(m.Version)
}

func (m *ModuleInfo) String() string {
	return m.Module + " " + m.Version
}

func readModuleInfo(raw []byte) (*ModuleInfo, int, error) {
	module, length, err := readString(raw, 0)
	if err != nil {
		return nil, 0, err
	}

	version, length, err := readString(raw, length)
	if err != nil {
		return nil, 0, err
	}

	return &ModuleInfo{Module: module, Version: version}, length, nil
}

func (m *ModuleInfo) Encode(buf []byte, offset int) int {
	offset = writeString(buf, offset, m.Module)
	offset = writeString(buf, offset, m.Version)

	return offset
}

type HandshakeRequest struct {
	Modules []ModuleInfo
}

func (p *HandshakeRequest) Type() PacketType {
	return HandshakeRequestPacket
}

func (p *HandshakeRequest) Encode() []byte {
	moduleCount := len(p.Modules)
	length := 2

	for _, module := range p.Modules {
		length += module.EncodedLen()
	}

	offset := 0

	buf := make([]byte, length)
	binary.BigEndian.PutUint16(buf[offset:], uint16(moduleCount))
	offset += 2

	for _, module := range p.Modules {
		log.Printf("module: %s", module.String())
		offset = module.Encode(buf, offset)
	}

	return buf
}

func DecodeHandshakeRequest(raw []byte) (*HandshakeRequest, error) {
	if len(raw) < 2 {
		return nil, io.ErrUnexpectedEOF
	}

	moduleCount := binary.BigEndian.Uint16(raw[:2])
	raw = raw[2:]

	modules := make([]ModuleInfo, moduleCount)

	for i := 0; i < int(moduleCount); i++ {
		module, length, err := readModuleInfo(raw)
		if err != nil {
			return nil, err
		}

		raw = raw[length:]
		modules[i] = *module
	}

	return &HandshakeRequest{Modules: modules}, nil
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
