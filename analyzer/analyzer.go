package analyzer

import (
	"shadownet/utils"
	"sync"
	"time"
)

// Threat represents a detected threat
type Threat struct {
    IP string
    AttackCount int
    LastSeen time.Time
    AttackTypes []string
    Risk float64
}

// Analyzer handles attack pattern analysis
type Analyzer struct {
    threats map[string]*Threat
    mu sync.RWMutex
}

// NewAnalyzer creates a new analyzer instance
func NewAnalyzer() *Analyzer {
    return &Analyzer{
        threats: make(map[string]*Threat),
    }
}

// Start begins the analysis process
func (a *Analyzer) Start() error {
    utils.Log.Info("Starting threat analyzer...")
    return nil
}

// AddAttack records a new attack attempt
func (a *Analyzer) AddAttack(ip, attackType string) {
    a.mu.Lock()
    defer a.mu.Unlock()

    threat, exists := a.threats[ip]
    if !exists {
        threat = &Threat{
            IP: ip,
            AttackTypes: make([]string, 0),
        }
        a.threats[ip] = threat
    }

    threat.AttackCount++
    threat.LastSeen = time.Now()
    
    // Check if this is a new attack type for this IP
    isNewType := true
    for _, t := range threat.AttackTypes {
        if t == attackType {
            isNewType = false
            break
        }
    }
    if isNewType {
        threat.AttackTypes = append(threat.AttackTypes, attackType)
    }

    // Update risk score based on attack patterns
    threat.Risk = a.calculateRisk(threat)
}

// calculateRisk determines the threat level of an attacker
func (a *Analyzer) calculateRisk(t *Threat) float64 {
    // Base risk starts at 0.1
    risk := 0.1

    // Increase risk based on attack count
    if t.AttackCount > 10 {
        risk += 0.3
    } else if t.AttackCount > 5 {
        risk += 0.2
    }

    // Increase risk based on variety of attack types
    if len(t.AttackTypes) > 2 {
        risk += 0.3
    }

    // Increase risk based on recency
    if time.Since(t.LastSeen) < 5*time.Minute {
        risk += 0.2
    }

    // Cap risk at 1.0
    if risk > 1.0 {
        risk = 1.0
    }

    return risk
}

// GetTopThreats returns the most serious threats
func (a *Analyzer) GetTopThreats() []Threat {
    a.mu.RLock()
    defer a.mu.RUnlock()

    // Convert threats map to slice for sorting
    threats := make([]Threat, 0, len(a.threats))
    for _, t := range a.threats {
        threats = append(threats, *t)
    }

    // Sort by risk score (descending)
    // In a real implementation, we would sort here
    // For now, just return all threats
    return threats
}

// GetThreatByIP retrieves threat information for a specific IP
func (a *Analyzer) GetThreatByIP(ip string) (Threat, bool) {
    a.mu.RLock()
    defer a.mu.RUnlock()

    if threat, exists := a.threats[ip]; exists {
        return *threat, true
    }
    return Threat{}, false
}