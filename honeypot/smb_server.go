package honeypot

import (
	"fmt"
	"net"
	"shadownet/db"
	"shadownet/utils"
)

// SMBServer mocks SMB protocol
type SMBServer struct {
    Port int
}

// StartSMPServer starts a fake SMB listener
func StartSMPServer(port int) {
    listener, _ := net.Listen("tcp", fmt.Sprintf(":%d", port))
    utils.Log.Infof("SMB honeypot running on port %d", port)

    for {
        conn, _ := listener.Accept()
        go handleSMB(conn)
    }
}

func handleSMB(conn net.Conn) {
    defer conn.Close()
    buf := make([]byte, 1024)
    conn.Read(buf)

    ip := conn.RemoteAddr().String()
    utils.Log.Warningf("SMB connection attempt from %s", ip)
    db.LogAttack(ip, "N/A", "smb")

    conn.Write([]byte("\xff\x53\x4d\x42")) // SMB protocol signature
}