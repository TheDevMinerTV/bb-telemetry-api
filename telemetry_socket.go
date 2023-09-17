package main

import (
	"bb-telemetry-api/packets"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
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
		log.Printf("Error setting TCP keepalive for %s: %s", s.addr, err)
		return
	}

	if err := s.conn.SetKeepAlivePeriod(5 * time.Second); err != nil {
		log.Printf("Error setting TCP keepalive period for %s: %s", s.addr, err)
		return
	}

	buffer := make([]byte, 4096)
	toParse := make([]byte, 0)

	for {
		n, err := s.conn.Read(buffer)
		if err != nil {
			log.Printf("Error reading TCP data from %s: %s", s.addr, err)
			return
		}

		toParse = append(toParse, buffer[:n]...)

		for {
			if len(toParse) < 2 {
				break
			}

			length := binary.BigEndian.Uint16(toParse[:2])
			if int(length) > len(toParse)-2 {
				break
			}

			toParse = toParse[2:]
			log.Printf("Received %d bytes from %s", length, s.addr)
			data := toParse[:length]
			toParse = toParse[length:]

			log.Printf("data: %+v", data)
			log.Printf("toParse: %+v", toParse)

			packet, err := packets.Parse(data)
			if err != nil {
				log.Printf("Error parsing packet from %s: %s", s.addr, err)
				continue
			}

			switch packet.Inner.Type() {
			case packets.HandshakeRequestPacket:
				log.Printf("Received handshake request from %s", s.addr)

				inner := packet.Inner.(*packets.HandshakeRequest)
				s.handshakeData = &HandshakeData{
					name:    inner.Module,
					version: inner.Version,
				}

				h := hmac.New(sha256.New, s.key[:])
				h.Write([]byte(inner.Module + ":" + inner.Version))
				s.expectedKey = h.Sum(nil)

				log.Printf("key: %+v", s.key)
				log.Printf("expected hmac: %+v", s.expectedKey)
				p2 := packets.NewWrapped(packets.NewHandshakeResponse(s.key))
				if _, err := s.conn.Write(p2.Encode()); err != nil {
					log.Printf("Error writing handshake response to %s: %s", s.addr, err)
				}

			case packets.StartRequestPacket:
				log.Printf("Received start request from %s", s.addr)

				inner := packet.Inner.(*packets.StartRequest)
				s.valid = hmac.Equal(inner.HMAC[:], s.expectedKey)

				if s.valid {
					log.Printf("HMAC from %s is valid", s.addr)

					runningInstances.With(map[string]string{
						"module":  s.handshakeData.name,
						"version": s.handshakeData.version,
					}).Inc()
				} else {
					log.Printf("HMAC from %s is invalid", s.addr)
				}

				p2 := packets.NewWrapped(&packets.StartResponse{})
				if _, err := s.conn.Write(p2.Encode()); err != nil {
					log.Printf("Error writing start response to %s: %s", s.addr, err)
				}

			case packets.HeartbeatRequestPacket:
				log.Printf("Received heartbeat request from %s", s.addr)
			}
		}
	}
}
