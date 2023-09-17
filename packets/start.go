package packets

import "io"

type StartRequest struct {
	HMAC [32]byte
}

func (p *StartRequest) Type() PacketType {
	return StartRequestPacket
}

func (p *StartRequest) Encode() []byte {
	buf := make([]byte, 32)

	copy(buf, p.HMAC[:])

	return buf
}

func DecodeStartRequest(raw []byte) (*StartRequest, error) {
	if len(raw) < 32 {
		return nil, io.ErrUnexpectedEOF
	}

	hash := [32]byte{}
	copy(hash[:], raw[:32])

	return &StartRequest{
		HMAC: hash,
	}, nil
}

type StartResponse struct {
}

func (p *StartResponse) Type() PacketType {
	return StartResponsePacket
}

func (p *StartResponse) Encode() []byte {
	return []byte{}
}
