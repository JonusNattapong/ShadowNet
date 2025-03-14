package honeypot

import (
	"fmt"
	"net"
	"shadownet/utils"
)

// StartModbusServer mocks a Modbus TCP server
func StartModbusServer(port int) {
    listener, _ := net.Listen("tcp", fmt.Sprintf(":%d", port))
    utils.Log.Infof("Modbus honeypot running on port %d", port)

    for {
        conn, _ := listener.Accept()
        go handleModbus(conn)
    }
}

func handleModbus(conn net.Conn) {
    defer conn.Close()
    buf := make([]byte, 1024)
    conn.Read(buf)

    ip := conn.RemoteAddr().String()
    utils.Log.Warningf("Modbus connection attempt from %s", ip)

    conn.Write([]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x06}) // Mock Modbus packet
}