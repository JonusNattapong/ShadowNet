package honeypot

import (
	"fmt"
	"net"
	"shadownet/db"
	"shadownet/utils"
)

// RDPServer mocks RDP handshake
type RDPServer struct {
    Port int
}

// StartRDPServer starts a fake RDP listener
func StartRDPServer(port int) {
    listener, _ := net.Listen("tcp", fmt.Sprintf(":%d", port))
    utils.Log.Infof("RDP honeypot running on port %d", port)

    for {
        conn, _ := listener.Accept()
        go handleRDP(conn)
    }
}

func handleRDP(conn net.Conn) {
    defer conn.Close()
    buf := make([]byte, 1024)
    conn.Read(buf)

    ip := conn.RemoteAddr().String()
    utils.Log.Warningf("RDP connection attempt from %s", ip)
    db.LogAttack(ip, "N/A", "rdp")

    conn.Write([]byte{0x03, 0x00, 0x00, 0x13}) // Mock RDP protocol handshake
}