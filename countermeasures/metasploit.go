package countermeasures

import (
	"fmt"
	"os/exec"
	"shadownet/utils"
)

// RunMetasploit runs an exploit via Metasploit
func RunMetasploit(targetIP, exploit string) {
    cmd := exec.Command("msfconsole", "-q", "-x", fmt.Sprintf("use %s; set RHOSTS %s; run", exploit, targetIP))
    output, _ := cmd.Output()
    utils.Log.Warningf("Exploiting target %s with %s: %s", targetIP, exploit, output)
}