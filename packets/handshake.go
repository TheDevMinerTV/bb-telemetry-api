package packets

import (
	"encoding/binary"
	"io"
)

type ModuleInfo struct {
	Name    string
	Version string
	Hash    string
}

func (m *ModuleInfo) EncodedLen() int {
	return encodedStringLength(m.Name) + encodedStringLength(m.Version)
}

func (m *ModuleInfo) String() string {
	return m.Name + " " + m.Version + " " + m.Hash
}

func readModuleInfo(raw []byte) (*ModuleInfo, int, error) {
	name, length, err := readString(raw, 0)
	if err != nil {
		return nil, 0, err
	}

	version, length, err := readString(raw, length)
	if err != nil {
		return nil, 0, err
	}

	hash, length, err := readString(raw, length)
	if err != nil {
		return nil, 0, err
	}

	return &ModuleInfo{Name: name, Version: version, Hash: hash}, length, nil
}

func (m *ModuleInfo) Encode(buf []byte, offset int) int {
	offset = writeString(buf, offset, m.Name)
	offset = writeString(buf, offset, m.Version)
	offset = writeString(buf, offset, m.Hash)

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
