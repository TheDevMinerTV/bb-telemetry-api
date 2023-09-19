package main

import (
	"bb-telemetry-api/packets"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"log"
	"net"
	"time"
)

type TelemetrySocket struct {
	verbose bool

	conn *net.TCPConn
	addr string
	key  [32]byte

	handshakeData *HandshakeData
	expectedKey   []byte

	valid bool
}

type HandshakeData struct {
	Modules []packets.ModuleInfo
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

func NewTelemetrySocket(conn *net.TCPConn, verbose bool) (*TelemetrySocket, error) {
	secret, err := generateKey()
	if err != nil {
		return nil, err
	}

	return &TelemetrySocket{
		verbose:       verbose,
		conn:          conn,
		addr:          conn.RemoteAddr().String(),
		key:           secret,
		handshakeData: nil,
	}, nil
}

func (s *TelemetrySocket) handle() {
	defer func() {
		if !s.valid {
			return
		}

		currentConnections.Dec()

		if s.handshakeData != nil {
			for _, module := range s.handshakeData.Modules {
				runningModules.With(map[string]string{
					"name":    module.Name,
					"version": module.Version,
					"hash":    module.Hash,
				}).Dec()
			}
		}
	}()
	defer func() {
		if err := recover(); err != nil {
			log.Printf("panic in telemetry socket from %s: %s", s.addr, err)
		}
	}()

	if err := s.conn.SetKeepAlive(true); err != nil {
		log.Printf("failed to enable TCP keepalive for %s: %s", s.addr, err)
		return
	}

	if err := s.conn.SetKeepAlivePeriod(10 * time.Second); err != nil {
		log.Printf("failed to set TCP keepalive period for %s: %s", s.addr, err)
		return
	}

	buffer := make([]byte, 4096)
	toParse := make([]byte, 0)

	for {
		n, err := s.conn.Read(buffer)
		if err != nil {
			if s.verbose {
				log.Printf("failed to read from %s: %s", s.addr, err)
			}
			return
		}

		toParse = append(toParse, buffer[:n]...)

		for {
			if len(toParse) < packets.DataLengthSize {
				break
			}

			length := packets.ReadLength(toParse)
			if length > len(toParse)-packets.DataLengthSize+packets.PacketTypeLength {
				if s.verbose {
					log.Printf("packet from %s is too short: need %d bytes, have %d bytes", s.addr, length+packets.DataLengthSize+packets.PacketTypeLength, len(toParse))
				}
				break
			}

			toParse = toParse[packets.DataLengthSize:]
			data := toParse[:packets.PacketTypeLength+length]
			toParse = toParse[packets.PacketTypeLength+length:]

			packet, err := packets.Parse(data)
			if err != nil {
				if s.verbose {
					log.Printf("failed to parse packet from %s: %s", s.addr, err)
				}
				continue
			}

			if s.verbose {
				log.Printf("received packet from %s: %d %+v", s.addr, packet.Inner.Type(), packet.Inner)
			}

			switch packet.Inner.Type() {
			case packets.HandshakeRequestPacket:
				inner := packet.Inner.(*packets.HandshakeRequest)
				s.handshakeData = &HandshakeData{
					Modules: inner.Modules,
				}

				h := hmac.New(sha256.New, s.key[:])
				for _, module := range inner.Modules {
					moduleBytes := []byte(module.String())
					if s.verbose {
						log.Printf("module bytes %s: %s", module.String(), hex.EncodeToString(moduleBytes))
					}
					h.Write(moduleBytes)
				}
				s.expectedKey = h.Sum(nil)

				if s.verbose {
					log.Printf("sent key to %s: %s", s.addr, hex.EncodeToString(s.key[:]))
				}

				p2 := packets.NewWrapped(packets.NewHandshakeResponse(s.key))
				if _, err := s.conn.Write(p2.Encode()); err != nil {
					log.Printf("failed to write handshake response to %s: %s", s.addr, err)
					return
				}

			case packets.StartRequestPacket:
				inner := packet.Inner.(*packets.StartRequest)
				s.valid = hmac.Equal(inner.HMAC[:], s.expectedKey)

				if s.valid {
					if s.verbose {
						log.Printf("%s successfully authenticated", s.addr)
					}

					for _, module := range s.handshakeData.Modules {
						runningModules.With(map[string]string{
							"name":    module.Name,
							"version": module.Version,
							"hash":    module.Hash,
						}).Inc()
					}

					currentConnections.Inc()
				} else {
					if s.verbose {
						log.Printf("%s failed to authenticate", s.addr)
						log.Printf("expected: %s", hex.EncodeToString(s.expectedKey))
						log.Printf("got:      %s", hex.EncodeToString(inner.HMAC[:]))
					}
				}

				p2 := packets.NewWrapped(&packets.StartResponse{})
				if _, err := s.conn.Write(p2.Encode()); err != nil {
					log.Printf("failed to write start response to %s: %s", s.addr, err)
					return
				}

			case packets.HeartbeatRequestPacket:
				if !s.valid {
					return
				}

				if s.verbose {
					log.Printf("%s sent heartbeat", s.addr)
				}
			}
		}
	}
}
