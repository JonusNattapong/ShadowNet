package honeypot

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"shadownet/db"
	"shadownet/utils"

	"golang.org/x/crypto/ssh"
)

// SSHServer implements a fake SSH server
type SSHServer struct {
    BaseHoneypot
    config *ssh.ServerConfig
}

// StartSSHServer starts a fake SSH server with proper error handling
func StartSSHServer(port int) error {
    sshServer := &SSHServer{
        BaseHoneypot: BaseHoneypot{
            Name: "SSH",
            Port: port,
        },
    }

    // Initialize SSH server config
    config := &ssh.ServerConfig{
        PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
            ip := c.RemoteAddr().String()
            user := c.User()
            utils.Log.Warningf("SSH login attempt from %s: user=%s, pass=%s", ip, user, string(pass))
            db.LogAttack(ip, fmt.Sprintf("user:%s,pass:%s", user, string(pass)), "ssh")
            return nil, fmt.Errorf("access denied")
        },
    }

    // Generate the RSA key
    privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
    if err != nil {
        return fmt.Errorf("failed to generate private key: %v", err)
    }

    // Generate PEM block for logging purposes
    privateKeyPEM := pem.EncodeToMemory(&pem.Block{
        Type:  "RSA PRIVATE KEY",
        Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
    })
    utils.Log.Debugf("Generated SSH host key: %s", string(privateKeyPEM))

    signer, err := ssh.NewSignerFromKey(privateKey)
    if err != nil {
        return fmt.Errorf("failed to create signer: %v", err)
    }

    config.AddHostKey(signer)
    sshServer.config = config

    // Initialize the base honeypot
    if err := sshServer.Initialize(port); err != nil {
        return err
    }

    ctx, cancel := context.WithCancel(context.Background())
    defer cancel()

    return sshServer.Start(ctx, sshServer.handleSSH)
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

    // Log the connection attempt with client version
    s.LogConnection(conn, []byte(fmt.Sprintf("Client Version: %s", string(sshConn.ClientVersion()))))

    // Even though we'll never reach here (as auth always fails), 
    // proper handling of channels and requests
    go ssh.DiscardRequests(reqs)
    for ch := range chans {
        ch.Reject(ssh.Prohibited, "Not implemented")
    }
}