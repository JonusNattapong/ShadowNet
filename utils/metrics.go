package utils

import (
	"context"
	"runtime"
	"sync"
	"time"
)

// AttackMetrics tracks information about attacks
type AttackMetrics struct {
	TotalAttacks     int
	UniqueIPs        map[string]int
	AttacksPerHour   map[int]int
	AttacksByService map[string]int
	mutex            sync.RWMutex
}

// SystemMetrics tracks system resource usage
type SystemMetrics struct {
	CPUUsage     float64
	MemoryUsage  uint64
	NumGoroutine int
}

// MetricsCollector gathers and provides metrics
type MetricsCollector struct {
	Attack  AttackMetrics
	System  SystemMetrics
	started time.Time
}

// NewMetricsCollector creates a new metrics collector
func NewMetricsCollector() *MetricsCollector {
	return &MetricsCollector{
		Attack: AttackMetrics{
			UniqueIPs:        make(map[string]int),
			AttacksPerHour:   make(map[int]int),
			AttacksByService: make(map[string]int),
		},
		started: time.Now(),
	}
}

// Start begins periodic collection of metrics
func (mc *MetricsCollector) Start(ctx context.Context) {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			mc.collectSystemMetrics()
		}
	}
}

// collectSystemMetrics gathers system-level metrics
func (mc *MetricsCollector) collectSystemMetrics() {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	mc.System.MemoryUsage = memStats.Alloc
	mc.System.NumGoroutine = runtime.NumGoroutine()
	// CPU usage would require additional packages like gopsutil
}

// RecordAttack registers an attack in the metrics
func (mc *MetricsCollector) RecordAttack(ip, service string) {
	mc.Attack.mutex.Lock()
	defer mc.Attack.mutex.Unlock()

	mc.Attack.TotalAttacks++
	mc.Attack.UniqueIPs[ip]++
	mc.Attack.AttacksByService[service]++

	currentHour := time.Now().Hour()
	mc.Attack.AttacksPerHour[currentHour]++
}

// GetUptime returns the system uptime
func (mc *MetricsCollector) GetUptime() time.Duration {
	return time.Since(mc.started)
}

// GetAttackStats returns a copy of the current attack statistics
func (mc *MetricsCollector) GetAttackStats() *AttackMetrics {
	mc.Attack.mutex.RLock()
	defer mc.Attack.mutex.RUnlock()

	// Create a deep copy to avoid concurrent access issues
	stats := &AttackMetrics{
		TotalAttacks:     mc.Attack.TotalAttacks,
		UniqueIPs:        make(map[string]int),
		AttacksPerHour:   make(map[int]int),
		AttacksByService: make(map[string]int),
	}

	for ip, count := range mc.Attack.UniqueIPs {
		stats.UniqueIPs[ip] = count
	}

	for hour, count := range mc.Attack.AttacksPerHour {
		stats.AttacksPerHour[hour] = count
	}

	for service, count := range mc.Attack.AttacksByService {
		stats.AttacksByService[service] = count
	}

	return stats
}
