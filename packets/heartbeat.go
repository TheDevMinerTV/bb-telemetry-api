package packets

type HeartbeatRequest struct{}

func (p *HeartbeatRequest) Type() PacketType {
	return HeartbeatRequestPacket
}

func (p *HeartbeatRequest) Encode() []byte {
	return []byte{}
}

func DecodeHeartbeatRequest() (*HeartbeatRequest, error) {
	return &HeartbeatRequest{}, nil
}
