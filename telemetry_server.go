package main

import (
	"log"
	"net"
)

type TelemetryServer struct {
	listener *net.TCPListener
}

func NewTelemetryServer() *TelemetryServer {
	return &TelemetryServer{}
}

func (s *TelemetryServer) Listen(rawAddr string) error {
	addr, err := net.ResolveTCPAddr("tcp", rawAddr)
	if err != nil {
		log.Println("Error resolving TCP address:", err)
		return err
	}

	conn, err := net.ListenTCP("tcp", addr)
	if err != nil {
		log.Println("Error creating TCP connection:", err)
		return err
	}

	log.Println("Listening for telemetry on", addr)

	s.listener = conn

	return nil
}

func (s *TelemetryServer) Close() error {
	return s.listener.Close()
}

func (s *TelemetryServer) run() {
	for {
		conn, err := s.listener.AcceptTCP()
		if err != nil {
			log.Println("Error accepting TCP connection:", err)
			continue
		}

		log.Println("New TCP connection from", conn.RemoteAddr())

		sock, err := NewTelemetrySocket(conn)
		if err != nil {
			log.Println("Error creating telemetry socket:", err)
			continue
		}

		go func() {
			defer func() {
				if err := recover(); err != nil {
					log.Println("Error handling telemetry socket:", err)
				}
			}()

			sock.handle()
		}()
	}
}
