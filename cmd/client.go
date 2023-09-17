package main

import (
	"bb-telemetry-api/packets"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"log"
	"net"
	"sync"
	"time"
)

func run() {
	modules := []packets.ModuleInfo{
		{
			Module:  "test",
			Version: "1.0.0",
		},
	}

	addr, err := net.ResolveTCPAddr("tcp", "raw.devminer.xyz:65500")
	if err != nil {
		log.Fatalln("Error resolving TCP address:", err)
	}

	conn, err := net.DialTCP("tcp", nil, addr)
	if err != nil {
		log.Fatalln("Error creating TCP connection:", err)
	}

	if err := conn.SetKeepAlive(true); err != nil {
		log.Fatalln("Error setting keep alive:", err)
	}

	if err := conn.SetKeepAlivePeriod(10 * time.Second); err != nil {
		log.Fatalln("Error setting keep alive period:", err)
	}

	p := packets.NewWrapped(&packets.HandshakeRequest{
		Modules: modules,
	}).Encode()
	log.Printf("handshake request: %s", hex.EncodeToString(p))
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
	for _, module := range modules {
		h.Write([]byte(module.String()))
	}
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
		time.Sleep(30 * time.Second)

		p = packets.NewWrapped(&packets.HeartbeatRequest{}).Encode()
		if _, err := conn.Write(p); err != nil {
			log.Fatalln("Error writing heartbeat request:", err)
		}
	}
}

var fConnections = flag.Int("connections", 1, "number of connections to make")
var fSpread = flag.Duration("spread", 100*time.Millisecond, "time to wait between connections")

func main() {
	flag.Parse()

	wg := sync.WaitGroup{}

	for i := 0; i < *fConnections; i++ {
		wg.Add(1)

		go func() {
			defer wg.Done()
			defer func() {
				if err := recover(); err != nil {
					log.Printf("panic: %v", err)
				}
			}()

			run()
		}()

		time.Sleep(*fSpread)
	}

	wg.Wait()
}
