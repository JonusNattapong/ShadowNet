package honeypot

import (
	"context"
	"net"
	"shadownet/db"
	"shadownet/utils"
)

// MQTTServer implements a fake MQTT broker
type MQTTServer struct {
    BaseHoneypot
}

// StartMQTTServer starts a fake MQTT listener with proper error handling
func StartMQTTServer(port int) error {
    mqtt := &MQTTServer{
        BaseHoneypot: BaseHoneypot{
            Name: "MQTT",
            Port: port,
        },
    }

    if err := mqtt.Initialize(port); err != nil {
        return err
    }

    ctx, cancel := context.WithCancel(context.Background())
    defer cancel()

    return mqtt.Start(ctx, mqtt.handleMQTT)
}

func (s *MQTTServer) handleMQTT(conn net.Conn) {
    defer conn.Close()
    
    buf := make([]byte, 1024)
    n, err := conn.Read(buf)
    if err != nil {
        utils.Log.Errorf("MQTT read error: %v", err)
        return
    }

    // Log the connection attempt
    hc := s.LogConnection(conn, buf[:n])
    
    // Log to database
    db.LogAttack(hc.IP, "N/A", "mqtt")

    // Send MQTT CONNECT acknowledgment packet
    // Fixed header: Packet type CONNACK (0x20), Remaining length 2 (0x02)
    // Variable header: Connect acknowledge flags 0x00, Connect return code 0x00 (Connection accepted)
    mqttResponse := []byte{0x20, 0x02, 0x00, 0x00}
    if _, err := conn.Write(mqttResponse); err != nil {
        utils.Log.Errorf("MQTT write error: %v", err)
    }
}