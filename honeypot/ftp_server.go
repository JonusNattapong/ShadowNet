package honeypot

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"shadownet/db"
	"shadownet/utils"
	"strings"
)

// FTPServer implements a fake FTP server
type FTPServer struct {
    BaseHoneypot
}

// StartFTPServer starts a fake FTP server with proper error handling
func StartFTPServer(port int) error {
    ftpServer := &FTPServer{
        BaseHoneypot: BaseHoneypot{
            Name: "FTP",
            Port: port,
        },
    }

    if err := ftpServer.Initialize(port); err != nil {
        return err
    }

    ctx, cancel := context.WithCancel(context.Background())
    defer cancel()

    return ftpServer.Start(ctx, ftpServer.handleFTP)
}

func (s *FTPServer) handleFTP(conn net.Conn) {
    defer conn.Close()

    // Log connection
    s.LogConnection(conn, []byte("FTP connection established"))

    reader := bufio.NewReader(conn)
    writer := bufio.NewWriter(conn)

    // Send welcome message
    writer.WriteString("220 FTP Server ready.\r\n")
    writer.Flush()

    var username string
    for {
        // Read command
        line, err := reader.ReadString('\n')
        if err != nil {
            utils.Log.Debugf("FTP read error: %v", err)
            return
        }

        line = strings.TrimSpace(line)
        parts := strings.SplitN(line, " ", 2)
        cmd := strings.ToUpper(parts[0])

        switch cmd {
        case "USER":
            if len(parts) < 2 {
                writer.WriteString("530 Please login with USER and PASS.\r\n")
                writer.Flush()
                continue
            }
            username = parts[1]
            writer.WriteString("331 Please specify the password.\r\n")

        case "PASS":
            if username == "" {
                writer.WriteString("503 Login with USER first.\r\n")
                writer.Flush()
                continue
            }

            password := ""
            if len(parts) > 1 {
                password = parts[1]
            }

            // Log the attack
            ip := conn.RemoteAddr().String()
            if idx := strings.LastIndex(ip, ":"); idx != -1 {
                ip = ip[:idx]
            }

            utils.Log.Warningf("FTP login attempt from %s: user=%s, pass=%s",
                ip, username, password)
            
            db.LogAttack(ip, fmt.Sprintf("user:%s,pass:%s", username, password), "ftp")
            
            writer.WriteString("530 Login incorrect.\r\n")
            username = ""

        case "QUIT":
            writer.WriteString("221 Goodbye.\r\n")
            writer.Flush()
            return

        default:
            writer.WriteString("530 Please login with USER and PASS.\r\n")
        }

        writer.Flush()
    }
}