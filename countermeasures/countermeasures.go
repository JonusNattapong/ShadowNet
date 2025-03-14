package countermeasures

import (
	"fmt"
	"os/exec"
	"shadownet/utils"
)

// Countermeasures handles defensive and offensive responses
type Countermeasures struct {
    enableExploits bool
}

// NewCountermeasures creates a new countermeasures instance
func NewCountermeasures(enableExploits bool) *Countermeasures {
    return &Countermeasures{
        enableExploits: enableExploits,
    }
}

// RunMetasploit executes a Metasploit exploit against a target
func (c *Countermeasures) RunMetasploit(ip, exploit string) error {
    if !c.enableExploits {
        return fmt.Errorf("exploits are disabled in configuration")
    }

    utils.Log.Warningf("Running Metasploit exploit %s against %s", exploit, ip)
    
    // Example of how to run msfconsole with a resource script
    cmd := exec.Command("msfconsole", "-q", "-x", fmt.Sprintf(`
        use %s
        set RHOST %s
        exploit
        exit
    `, exploit, ip))

    output, err := cmd.CombinedOutput()
    if err != nil {
        return fmt.Errorf("metasploit error: %v, output: %s", err, output)
    }

    utils.Log.Infof("Metasploit exploit completed against %s", ip)
    return nil
}

// BlockIP adds a firewall rule to block an IP
func (c *Countermeasures) BlockIP(ip string) error {
    utils.Log.Warningf("Blocking IP address: %s", ip)
    
    // Use iptables/netsh depending on OS
    var cmd *exec.Cmd
    if utils.IsLinux() {
        cmd = exec.Command("iptables", "-A", "INPUT", "-s", ip, "-j", "DROP")
    } else {
        cmd = exec.Command("netsh", "advfirewall", "firewall", "add", "rule",
            "name=block_attacker", "dir=in", "action=block",
            "remoteip="+ip)
    }

    if output, err := cmd.CombinedOutput(); err != nil {
        return fmt.Errorf("firewall error: %v, output: %s", err, output)
    }

    utils.Log.Infof("Successfully blocked IP: %s", ip)
    return nil
}

// UnblockIP removes firewall rules blocking an IP
func (c *Countermeasures) UnblockIP(ip string) error {
    utils.Log.Infof("Unblocking IP address: %s", ip)
    
    var cmd *exec.Cmd
    if utils.IsLinux() {
        cmd = exec.Command("iptables", "-D", "INPUT", "-s", ip, "-j", "DROP")
    } else {
        cmd = exec.Command("netsh", "advfirewall", "firewall", "delete", "rule",
            "name=block_attacker", "remoteip="+ip)
    }

    if output, err := cmd.CombinedOutput(); err != nil {
        return fmt.Errorf("firewall error: %v, output: %s", err, output)
    }

    utils.Log.Infof("Successfully unblocked IP: %s", ip)
    return nil
}