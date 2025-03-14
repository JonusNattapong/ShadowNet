package honeypot

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"shadownet/db"
	"shadownet/utils"
)

// ModbusServer implements a fake Modbus server
type ModbusServer struct {
    BaseHoneypot
}

// StartModbusServer starts a fake Modbus server with proper error handling
func StartModbusServer(port int) error {
    modbusServer := &ModbusServer{
        BaseHoneypot: BaseHoneypot{
            Name: "Modbus",
            Port: port,
        },
    }

    if err := modbusServer.Initialize(port); err != nil {
        return err
    }

    ctx, cancel := context.WithCancel(context.Background())
    defer cancel()

    return modbusServer.Start(ctx, modbusServer.handleModbus)
}

func (s *ModbusServer) handleModbus(conn net.Conn) {
    defer conn.Close()

    // Log the connection
    s.LogConnection(conn, []byte("Modbus connection established"))

    // Buffer for reading Modbus MBAP header (7 bytes) and PDU
    buf := make([]byte, 260) // Max Modbus message size

    for {
        // Read MBAP header (7 bytes)
        n, err := conn.Read(buf[:7])
        if err != nil || n != 7 {
            utils.Log.Debugf("Modbus read error: %v", err)
            return
        }

        // Parse MBAP header
        transactionID := binary.BigEndian.Uint16(buf[0:2])
        protocolID := binary.BigEndian.Uint16(buf[2:4])
        length := binary.BigEndian.Uint16(buf[4:6])
        unitID := buf[6]

        // Read PDU
        pduLen := int(length) - 1 // subtract unitID length
        if pduLen <= 0 || pduLen > 253 {
            utils.Log.Warningf("Invalid Modbus message length: %d", pduLen)
            return
        }

        n, err = conn.Read(buf[7 : 7+pduLen])
        if err != nil || n != pduLen {
            utils.Log.Debugf("Modbus PDU read error: %v", err)
            return
        }

        // Get function code
        functionCode := buf[7]

        // Log the attack
        ip := conn.RemoteAddr().String()
        if idx := net.JoinHostPort("", ip); idx != "" {
            ip = idx
        }

        attackData := make([]byte, 7+pduLen)
        copy(attackData, buf[:7+pduLen])
        
        utils.Log.Warningf("Modbus request from %s: Function=0x%02x, Unit=%d",
            ip, functionCode, unitID)
        
        db.LogAttack(ip, 
            fmt.Sprintf("function:0x%02x,unit:%d,transaction:%d",
                functionCode, unitID, transactionID),
            "modbus")

        // Prepare response
        response := make([]byte, 8) // MBAP header + function code + error code
        binary.BigEndian.PutUint16(response[0:2], transactionID)
        binary.BigEndian.PutUint16(response[2:4], protocolID)
        binary.BigEndian.PutUint16(response[4:6], 2) // length of unit ID + PDU
        response[6] = unitID
        response[7] = functionCode | 0x80 // Set error bit

        // Send response
        if _, err := conn.Write(response); err != nil {
            utils.Log.Debugf("Modbus write error: %v", err)
            return
        }
    }
}