package honeypot

import (
	"context"
	"net"
	"shadownet/db"
	"shadownet/utils"
)

// RDPServer implements a fake RDP server
type RDPServer struct {
    BaseHoneypot
}

// StartRDPServer starts a fake RDP listener with proper error handling
func StartRDPServer(port int) error {
    rdp := &RDPServer{
        BaseHoneypot: BaseHoneypot{
            Name: "RDP",
            Port: port,
        },
    }

    if err := rdp.Initialize(port); err != nil {
        return err
    }

    ctx, cancel := context.WithCancel(context.Background())
    defer cancel()

    return rdp.Start(ctx, rdp.handleRDP)
}

func (s *RDPServer) handleRDP(conn net.Conn) {
    defer conn.Close()
    
    buf := make([]byte, 1024)
    n, err := conn.Read(buf)
    if err != nil {
        utils.Log.Errorf("RDP read error: %v", err)
        return
    }

    // Log the connection attempt
    hc := s.LogConnection(conn, buf[:n])
    
    // Log to database
    db.LogAttack(hc.IP, "N/A", "rdp")

    // Send RDP protocol handshake
    rdpHandshake := []byte{0x03, 0x00, 0x00, 0x13} // Standard RDP protocol header
    if _, err := conn.Write(rdpHandshake); err != nil {
        utils.Log.Errorf("RDP write error: %v", err)
    }
}