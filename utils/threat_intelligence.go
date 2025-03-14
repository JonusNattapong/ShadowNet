package utils

import (
	"context"
	"net/http"
	"sync"
	"time"
)

// ThreatInfo represents information about a known threat
type ThreatInfo struct {
	IP          string
	Reputation  float64
	Categories  []string
	LastUpdated time.Time
	Source      string
}

// ThreatIntelligence manages threat information
type ThreatIntelligence struct {
	knownThreats map[string]ThreatInfo
	mutex        sync.RWMutex
	client       *http.Client
}

// NewThreatIntelligence creates a new threat intelligence manager
func NewThreatIntelligence() *ThreatIntelligence {
	return &ThreatIntelligence{
		knownThreats: make(map[string]ThreatInfo),
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// Start begins periodic updates of threat intelligence
func (ti *ThreatIntelligence) Start(ctx context.Context) {
	// Initial load
	ti.updateThreatFeeds()

	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			ti.updateThreatFeeds()
		}
	}
}

// updateThreatFeeds refreshes threat data from external sources
func (ti *ThreatIntelligence) updateThreatFeeds() {
	// Example sources - in production, use real threat intelligence APIs
	sources := []string{
		"https://threatfeed.example.com/api/v1/threats",
		"https://blocklist.example.org/known-attackers",
	}

	for _, source := range sources {
		ti.fetchThreatData(source)
	}

	Log.Infof("Updated threat intelligence database with %d known threats", len(ti.knownThreats))
}

// fetchThreatData gets threat data from a specific source
func (ti *ThreatIntelligence) fetchThreatData(source string) {
	// In a real implementation, this would make HTTP requests to threat feeds
	// For now, we'll simulate with sample data
	
	// Simulating data that would come from an API
	sampleData := []struct {
		IP         string   `json:"ip"`
		Score      float64  `json:"risk_score"`
		Categories []string `json:"categories"`
	}{
		{"192.168.1.100", 0.85, []string{"malware", "scanner"}},
		{"10.0.0.5", 0.92, []string{"botnet", "bruteforce"}},
	}

	ti.mutex.Lock()
	defer ti.mutex.Unlock()

	for _, threat := range sampleData {
		ti.knownThreats[threat.IP] = ThreatInfo{
			IP:          threat.IP,
			Reputation:  threat.Score,
			Categories:  threat.Categories,
			LastUpdated: time.Now(),
			Source:      source,
		}
	}
}

// IsKnownThreat checks if an IP is a known threat
func (ti *ThreatIntelligence) IsKnownThreat(ip string) (bool, ThreatInfo) {
	ti.mutex.RLock()
	defer ti.mutex.RUnlock()
	
	threat, exists := ti.knownThreats[ip]
	return exists, threat
}

// AddThreat adds a new threat to the database
func (ti *ThreatIntelligence) AddThreat(ip string, categories []string, reputation float64) {
	ti.mutex.Lock()
	defer ti.mutex.Unlock()
	
	ti.knownThreats[ip] = ThreatInfo{
		IP:          ip,
		Reputation:  reputation,
		Categories:  categories,
		LastUpdated: time.Now(),
		Source:      "local",
	}
}
