package main

import (
	"bb-telemetry-api/packets"
	"crypto/hmac"
	"crypto/sha256"
	"log"
	"net"
	"time"
)

const (
	Module  = "tes3t"
	Version = "1.0.30"
)

func main() {
	addr, err := net.ResolveTCPAddr("tcp", "127.0.0.1:65500")
	if err != nil {
		log.Fatalln("Error resolving TCP address:", err)
	}

	conn, err := net.DialTCP("tcp", nil, addr)
	if err != nil {
		log.Fatalln("Error creating TCP connection:", err)
	}

	p := packets.NewWrapped(&packets.HandshakeRequest{
		Module:  Module,
		Version: Version,
	}).Encode()
	if _, err := conn.Write(p); err != nil {
		log.Fatalln("Error writing handshake request:", err)
	}
	log.Printf("wrote handshake request")

	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil {
		log.Fatalln("Error reading handshake response:", err)
	}
	log.Printf("read handshake response")

	data := buf[:n]

	data = data[packets.DataLengthSize:]
	p2, err := packets.Parse(data)
	if err != nil {
		log.Fatalln("Error parsing handshake response:", err)
	}

	if p2.Inner.Type() != packets.HandshakeResponsePacket {
		log.Fatalln("Error: expected handshake response, got", p2.Inner.Type())
	}

	p3 := p2.Inner.(*packets.HandshakeResponse)

	log.Printf("key: %+v", p3.Key)
	h := hmac.New(sha256.New, p3.Key[:])
	h.Write([]byte(Module + ":" + Version))
	hc := h.Sum(nil)
	log.Printf("hmac: %+v", hc)

	p = packets.NewWrapped(&packets.StartRequest{
		HMAC: [32]byte(hc),
	}).Encode()
	if _, err := conn.Write(p); err != nil {
		log.Fatalln("Error writing start request:", err)
	}
	log.Printf("wrote start request")

	n, err = conn.Read(buf)
	if err != nil {
		log.Fatalln("Error reading start response:", err)
	}
	log.Printf("read start response")

	data = buf[:n]

	data = data[packets.DataLengthSize:]
	p2, err = packets.Parse(data)
	if err != nil {
		log.Fatalln("Error parsing start response:", err)
	}

	if p2.Inner.Type() != packets.StartResponsePacket {
		log.Fatalln("Error: expected start response, got", p2.Inner.Type())
	}

	log.Printf("got start response")

	for {
		time.Sleep(1 * time.Second)
	}
}
