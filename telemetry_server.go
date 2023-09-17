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
		log.Println("failed to resolve telemetry listener address:", err)
		return err
	}

	conn, err := net.ListenTCP("tcp", addr)
	if err != nil {
		log.Println("failed to listen for telemetry:", err)
		return err
	}

	log.Println("listening for telemetry on", addr)

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
			log.Println("failed to accept telemetry connection:", err)
			continue
		}

		log.Printf("accepted telemetry connection from %s", conn.RemoteAddr())

		sock, err := NewTelemetrySocket(conn)
		if err != nil {
			log.Printf("failed to create telemetry socket from %s: %s", conn.RemoteAddr(), err)
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
