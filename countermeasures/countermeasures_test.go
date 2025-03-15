package countermeasures_test

import (
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"

	"shadownet/countermeasures"

	"github.com/stretchr/testify/suite"
	"golang.org/x/crypto/ssh"
)

// Helper functions to simulate attacks
func simulateSSHBruteForce(targetIP string) error {
    // Common usernames for brute force attempts
    usernames := []string{"admin", "root", "user", "test"}
    passwords := []string{"password", "123456", "admin123", "test123"}

    // Create SSH client config
    config := &ssh.ClientConfig{
        HostKeyCallback: ssh.InsecureIgnoreHostKey(),
        Timeout:         time.Second * 2,
    }

    // Simulate brute force attempts
    for _, user := range usernames {
        for _, pass := range passwords {
            config.User = user
            config.Auth = []ssh.AuthMethod{
                ssh.Password(pass),
            }

            // Attempt SSH connection
            client, err := ssh.Dial("tcp", targetIP+":22", config)
            if err == nil {
                client.Close()
            }

            time.Sleep(100 * time.Millisecond)
        }
    }
    return nil
}

func verifyIPBlocked(ip string) bool {
    var cmd *exec.Cmd
    
    if runtime.GOOS == "windows" {
        cmd = exec.Command("netsh", "advfirewall", "firewall", "show", "rule", "name=all")
    } else {
        cmd = exec.Command("iptables", "-L")
    }
    
    output, err := cmd.Output()
    if err != nil {
        return false
    }
    
    return strings.Contains(string(output), ip)
}

type CountermeasureTestSuite struct {
    suite.Suite
    cm *countermeasures.Countermeasures
}

func TestCountermeasureSuite(t *testing.T) {
    suite.Run(t, new(CountermeasureTestSuite))
}

func (s *CountermeasureTestSuite) SetupSuite() {
    s.cm = countermeasures.NewCountermeasures(true)
}

func (s *CountermeasureTestSuite) TearDownTest() {
    // Clean up any firewall rules or system changes
    if s.cm != nil {
        s.cm.UnblockIP("192.168.1.100")
        s.cm.UnblockIP("10.0.0.5")
    }
}

func (s *CountermeasureTestSuite) TestIPBlockingWithBruteForce() {
    // Simulate SSH brute force attack
    err := simulateSSHBruteForce("192.168.1.100")
    s.Require().NoError(err)

    // Block the attacking IP
    err = s.cm.BlockIP("192.168.1.100")
    s.Require().NoError(err)

    // Allow time for firewall rule to take effect
    time.Sleep(500 * time.Millisecond)

    // Verify IP is actually blocked
    s.True(verifyIPBlocked("192.168.1.100"))

    // Test unblocking
    err = s.cm.UnblockIP("192.168.1.100")
    s.Require().NoError(err)
    
    // Allow time for firewall rule to be removed
    time.Sleep(500 * time.Millisecond)
    
    s.False(verifyIPBlocked("192.168.1.100"))
}

func (s *CountermeasureTestSuite) TestMetasploitResponse() {
    // Test with exploits enabled
    err := s.cm.RunMetasploit("10.0.0.5", "exploit/windows/smb/ms17_010_eternalblue")
    s.Require().NoError(err)

    // Allow time for exploit execution
    time.Sleep(1 * time.Second)

    // Test with exploits disabled
    s.cm = countermeasures.NewCountermeasures(false)
    err = s.cm.RunMetasploit("10.0.0.5", "exploit/windows/smb/ms17_010_eternalblue")
    s.Require().Error(err)
    s.Contains(err.Error(), "exploits are disabled")
}

func (s *CountermeasureTestSuite) TestMultipleCountermeasures() {
    // Simulate multiple attacks and responses
    
    // First block an IP
    err := s.cm.BlockIP("192.168.1.100")
    s.Require().NoError(err)
    
    // Then run Metasploit module
    err = s.cm.RunMetasploit("192.168.1.100", "exploit/windows/smb/ms17_010_eternalblue")
    s.Require().NoError(err)

    // Allow time for both countermeasures to execute
    time.Sleep(1 * time.Second)

    // Verify IP is still blocked after Metasploit execution
    s.True(verifyIPBlocked("192.168.1.100"))
}
