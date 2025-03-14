package honeypot

import (
	"context"
	"net"
	"shadownet/db"
	"shadownet/utils"
)

// SMBServer implements a fake SMB server
type SMBServer struct {
    BaseHoneypot
}

// StartSMBServer starts a fake SMB listener with proper error handling
func StartSMBServer(port int) error {
    smb := &SMBServer{
        BaseHoneypot: BaseHoneypot{
            Name: "SMB",
            Port: port,
        },
    }

    if err := smb.Initialize(port); err != nil {
        return err
    }

    ctx, cancel := context.WithCancel(context.Background())
    defer cancel()

    return smb.Start(ctx, smb.handleSMB)
}

func (s *SMBServer) handleSMB(conn net.Conn) {
    defer conn.Close()
    
    buf := make([]byte, 1024)
    n, err := conn.Read(buf)
    if err != nil {
        utils.Log.Errorf("SMB read error: %v", err)
        return
    }

    // Log the connection attempt
    hc := s.LogConnection(conn, buf[:n])
    
    // Log to database
    db.LogAttack(hc.IP, "N/A", "smb")

    // Send SMB protocol signature (SMB\xFF) as response
    smbSignature := []byte{0x00, 0x53, 0x4D, 0x42, 0xFF}
    if _, err := conn.Write(smbSignature); err != nil {
        utils.Log.Errorf("SMB write error: %v", err)
    }
}