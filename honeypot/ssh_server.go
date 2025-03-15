package honeypot

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"fmt"
	"net"

	"shadownet/utils"

	"golang.org/x/crypto/ssh"
)

// SSHServer implements a fake SSH server
type SSHServer struct {
    BaseHoneypot
    config *ssh.ServerConfig
}

// NewSSHServer creates a new SSH honeypot
func NewSSHServer(db *sql.DB, port int) (*SSHServer, error) {
    sshServer := &SSHServer{
        BaseHoneypot: *NewBaseHoneypot("SSH", port, db),
    }

    // Initialize SSH server config
    config := &ssh.ServerConfig{
        PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
            ip := c.RemoteAddr().String()
            user := c.User()
            utils.Log.Warningf("Rejected SSH login attempt from %s - user:%s", ip, user)
            return nil, fmt.Errorf("access denied")
        },
    }

    // Generate the RSA key
    privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
    if err != nil {
        return nil, fmt.Errorf("failed to generate private key: %v", err)
    }

    // Generate PEM block for logging purposes
    privateKeyPEM := pem.EncodeToMemory(&pem.Block{
        Type:  "RSA PRIVATE KEY",
        Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
    })
    utils.Log.Debugf("Generated SSH host key: %s", string(privateKeyPEM))

    signer, err := ssh.NewSignerFromKey(privateKey)
    if err != nil {
        return nil, fmt.Errorf("failed to create signer: %v", err)
    }

    config.AddHostKey(signer)
    sshServer.config = config

    return sshServer, nil
}

// Start starts the SSH honeypot server
func (s *SSHServer) Start() error {
    if err := s.Initialize(s.Port); err != nil {
        return err
    }

    ctx, cancel := context.WithCancel(context.Background())
    defer cancel()

    return s.BaseHoneypot.Start(ctx, s.handleSSH)
}

func (s *SSHServer) handleSSH(conn net.Conn) {
    defer conn.Close()

    // Attempt SSH handshake
    sshConn, chans, reqs, err := ssh.NewServerConn(conn, s.config)
    if err != nil {
        // This is expected as we deny all auth attempts
        utils.Log.Debugf("SSH handshake error from %s: %v", conn.RemoteAddr(), err)
        return
    }
    defer sshConn.Close()

    // Just log the connection attempt
    remoteAddr := conn.RemoteAddr().String()
    clientVersion := string(sshConn.ClientVersion())
    utils.Log.Warningf("SSH connection attempt from %s with client version %s", remoteAddr, clientVersion)

    // Even though we'll never reach here (as auth always fails), 
    // proper handling of channels and requests
    go ssh.DiscardRequests(reqs)
    for ch := range chans {
        ch.Reject(ssh.Prohibited, "Not implemented")
    }
}
