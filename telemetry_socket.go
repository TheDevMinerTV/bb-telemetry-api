package main

import (
	"bb-telemetry-api/packets"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"log"
	"net"
	"time"
)

type TelemetrySocket struct {
	conn *net.TCPConn
	addr string
	key  [32]byte

	handshakeData *HandshakeData
	expectedKey   []byte

	valid bool
}

type HandshakeData struct {
	name    string
	version string
}

func generateKey() ([32]byte, error) {
	rawSecret := make([]byte, 32)
	_, err := rand.Read(rawSecret)
	if err != nil {
		return [32]byte{}, err
	}
	secret := [32]byte{}
	copy(secret[:], rawSecret)
	return secret, nil
}

func NewTelemetrySocket(conn *net.TCPConn) (*TelemetrySocket, error) {
	secret, err := generateKey()
	if err != nil {
		return nil, err
	}

	return &TelemetrySocket{
		conn:          conn,
		addr:          conn.RemoteAddr().String(),
		key:           secret,
		handshakeData: nil,
	}, nil
}

func (s *TelemetrySocket) handle() {
	defer func() {
		if s.handshakeData != nil {
			runningInstances.With(map[string]string{
				"module":  s.handshakeData.name,
				"version": s.handshakeData.version,
			}).Dec()
		}
	}()

	if err := s.conn.SetKeepAlive(true); err != nil {
		log.Printf("failed to enable TCP keepalive for %s: %s", s.addr, err)
		return
	}

	if err := s.conn.SetKeepAlivePeriod(5 * time.Second); err != nil {
		log.Printf("failed to set TCP keepalive period for %s: %s", s.addr, err)
		return
	}

	buffer := make([]byte, 4096)
	toParse := make([]byte, 0)

	for {
		n, err := s.conn.Read(buffer)
		if err != nil {
			log.Printf("failed to read from %s: %s", s.addr, err)
			return
		}

		toParse = append(toParse, buffer[:n]...)

		for {
			if len(toParse) < packets.DataLengthSize {
				break
			}

			length := packets.ReadLength(toParse)
			if length > len(toParse)-packets.DataLengthSize+packets.PacketTypeLength {
				log.Printf("packet from %s is too short: need %d bytes, have %d bytes", s.addr, length+packets.DataLengthSize+packets.PacketTypeLength, len(toParse))
				break
			}

			toParse = toParse[packets.DataLengthSize:]
			data := toParse[:packets.PacketTypeLength+length]
			toParse = toParse[packets.PacketTypeLength+length:]

			packet, err := packets.Parse(data)
			if err != nil {
				log.Printf("failed to parse packet from %s: %s", s.addr, err)
				continue
			}

			log.Printf("received packet from %s: %+v", s.addr, packet.Inner)

			switch packet.Inner.Type() {
			case packets.HandshakeRequestPacket:
				inner := packet.Inner.(*packets.HandshakeRequest)
				s.handshakeData = &HandshakeData{
					name:    inner.Module,
					version: inner.Version,
				}

				h := hmac.New(sha256.New, s.key[:])
				h.Write([]byte(inner.Module + ":" + inner.Version))
				s.expectedKey = h.Sum(nil)

				p2 := packets.NewWrapped(packets.NewHandshakeResponse(s.key))
				if _, err := s.conn.Write(p2.Encode()); err != nil {
					log.Printf("failed to write handshake response to %s: %s", s.addr, err)
					return
				}

			case packets.StartRequestPacket:
				inner := packet.Inner.(*packets.StartRequest)
				s.valid = hmac.Equal(inner.HMAC[:], s.expectedKey)

				if s.valid {
					log.Printf("%s successfully authenticated", s.addr)

					runningInstances.With(map[string]string{
						"module":  s.handshakeData.name,
						"version": s.handshakeData.version,
					}).Inc()
				} else {
					log.Printf("%s failed to authenticate", s.addr)
				}

				p2 := packets.NewWrapped(&packets.StartResponse{})
				if _, err := s.conn.Write(p2.Encode()); err != nil {
					log.Printf("failed to write start response to %s: %s", s.addr, err)
					return
				}

			case packets.HeartbeatRequestPacket:
				log.Printf("%s sent heartbeat", s.addr)
			}
		}
	}
}
