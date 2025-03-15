package types

import (
	"time"
)

// Attack types
const (
    AttackTypeSSHBruteForce   = "ssh_brute_force"
    AttackTypeSQLInjection    = "sql_injection"
    AttackTypePortScan        = "port_scan"
    AttackTypeXSS             = "xss"
    AttackTypeDirectoryTraversal = "directory_traversal"
)

// Attack represents a detected attack attempt
type Attack struct {
    ID        int64
    Type      string
    SourceIP  string
    Details   string
    Timestamp time.Time
}
