package honeypot

import (
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

// SSHServer represents a fake SSH honeypot
type SSHServer struct {
    Port int
}

// StartSSHServer starts a fake SSH server
func StartSSHServer(port int) {
    config := &ssh.ServerConfig{
        PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
            utils.Log.Warningf("SSH login attempt: user=%s, pass=%s", c.User(), string(pass))
            db.LogAttack(c.User(), string(pass), "ssh")
            return nil, fmt.Errorf("access denied")
        },
    }

    privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
    privateKeyPEM := &pem.Block{
        Type:  "RSA PRIVATE KEY",
        Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
    }
    config.AddHostKey(ssh.NewSignerFromKey(privateKey))

    listener, _ := net.Listen("tcp", fmt.Sprintf(":%d", port))
    utils.Log.Infof("SSH honeypot running on port %d", port)

    for {
        conn, _ := listener.Accept()
        _, _, _, _ = ssh.NewServerConn(conn, config)
    }
}