package honeypot

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"shadownet/utils"
	"time"
)

// HoneypotConnection represents a connection to a honeypot
type HoneypotConnection struct {
    IP        string
    Port      int
    Service   string
    Timestamp time.Time
    Data      []byte
}

// BaseHoneypot provides common functionality for all honeypots
type BaseHoneypot struct {
    Name     string
    Port     int
    Listener net.Listener
    Timeout  time.Duration
    DB       *sql.DB
}

// NewBaseHoneypot creates a new base honeypot instance
func NewBaseHoneypot(name string, port int, db *sql.DB) *BaseHoneypot {
    return &BaseHoneypot{
        Name:    name,
        Port:    port,
        DB:      db,
        Timeout: 30 * time.Second,
    }
}

// Initialize sets up the base honeypot
func (b *BaseHoneypot) Initialize(port int) error {
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return fmt.Errorf("failed to start %s honeypot on port %d: %v", b.Name, port, err)
	}
	
	b.Listener = listener
	b.Port = port
	if b.Timeout == 0 {
		b.Timeout = 30 * time.Second
	}
	
	return nil
}

// Start begins accepting connections with context for graceful shutdown
func (b *BaseHoneypot) Start(ctx context.Context, handler func(net.Conn)) error {
	utils.Log.Infof("%s honeypot running on port %d", b.Name, b.Port)
	
	go func() {
		<-ctx.Done()
		b.Listener.Close()
	}()
	
	for {
		// Use deadline to prevent blocking forever on accept
		b.Listener.(*net.TCPListener).SetDeadline(time.Now().Add(1 * time.Second))
		
		conn, err := b.Listener.Accept()
		if err != nil {
			if opErr, ok := err.(*net.OpError); ok && opErr.Timeout() {
				// Check if context is cancelled
				select {
				case <-ctx.Done():
					return nil
				default:
					continue
				}
			}
			utils.Log.Errorf("%s honeypot accept error: %v", b.Name, err)
			continue
		}
		
		// Set connection timeout
		conn.SetDeadline(time.Now().Add(b.Timeout))
		
		go func(c net.Conn) {
			defer func() {
				if r := recover(); r != nil {
					utils.Log.Errorf("%s honeypot handler panic: %v", b.Name, r)
				}
			}()
			
			handler(c)
		}(conn)
	}
}

// LogConnection records connection details
func (b *BaseHoneypot) LogConnection(conn net.Conn, data []byte) *HoneypotConnection {
	hc := &HoneypotConnection{
		IP:        conn.RemoteAddr().String(),
		Port:      b.Port,
		Service:   b.Name,
		Timestamp: time.Now(),
		Data:      data,
	}
	
	utils.Log.Warningf("%s connection attempt from %s", b.Name, hc.IP)
	return hc
}
