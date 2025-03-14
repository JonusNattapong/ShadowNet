package utils

import "os/exec"

// BlockIP blocks an IP using iptables
func BlockIP(ip string) {
    cmd := exec.Command("iptables", "-A", "INPUT", "-s", ip, "-j", "DROP")
    cmd.Run()
    Log.Warningf("Blocked IP: %s", ip)
}