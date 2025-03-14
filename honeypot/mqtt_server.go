package honeypot

import (
	"fmt"
	"net"
	"shadownet/utils"
)

// StartMQTTServer mocks an MQTT broker
func StartMQTTServer(port int) {
    listener, _ := net.Listen("tcp", fmt.Sprintf(":%d", port))
    utils.Log.Infof("MQTT honeypot running on port %d", port)

    for {
        conn, _ := listener.Accept()
        go handleMQTT(conn)
    }
}

func handleMQTT(conn net.Conn) {
    defer conn.Close()
    buf := make([]byte, 1024)
    conn.Read(buf)

    ip := conn.RemoteAddr().String()
    utils.Log.Warningf("MQTT connection attempt from %s", ip)

    conn.Write([]byte{0x10, 0x0C, 0x00, 0x04, 0x4D, 0x51, 0x54, 0x54}) // Mock MQTT CONNECT packet
}