package main

import (
	"context"
	"fmt"
	"net/http"
	"shadownet/utils"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// startAPIServer implements a REST API for system monitoring and control
func startAPIServer(ctx context.Context, port int, services map[string]*ServiceStatus, mu *sync.RWMutex) {
    router := gin.Default()

    // Health check endpoint
    router.GET("/health", func(c *gin.Context) {
        c.JSON(http.StatusOK, gin.H{
            "status": "healthy",
            "timestamp": time.Now(),
        })
    })

    // Services status endpoint
    router.GET("/services", func(c *gin.Context) {
        mu.RLock()
        defer mu.RUnlock()

        status := make(map[string]interface{})
        for name, service := range services {
            status[name] = gin.H{
                "name":   service.Name,
                "status": service.Status,
                "errors": service.Errors,
            }
        }

        c.JSON(http.StatusOK, gin.H{
            "services": status,
        })
    })

    // Metrics endpoint
    router.GET("/metrics", func(c *gin.Context) {
        metrics := utils.NewMetricsCollector().GetAttackStats()
        c.JSON(http.StatusOK, gin.H{
            "total_attacks":      metrics.TotalAttacks,
            "unique_ips":        len(metrics.UniqueIPs),
            "attacks_by_service": metrics.AttacksByService,
        })
    })

    // Threats endpoint
    router.GET("/threats", func(c *gin.Context) {
        c.JSON(http.StatusOK, gin.H{
            "active_threats": []string{}, // Would be populated from the analyzer
            "blocked_ips":   []string{}, // Would be populated from countermeasures
        })
    })

    // Configuration endpoint
    router.GET("/config", func(c *gin.Context) {
        c.JSON(http.StatusOK, gin.H{
            "honeypots_active": len(services),
            "ai_enabled":      true,
            "countermeasures": true,
        })
    })

    // Start server with graceful shutdown
    srv := &http.Server{
        Addr:    fmt.Sprintf(":%d", port),
        Handler: router,
    }

    go func() {
        if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
            utils.Log.Errorf("API server error: %v", err)
        }
    }()

    go func() {
        <-ctx.Done()
        shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
        defer cancel()

        if err := srv.Shutdown(shutdownCtx); err != nil {
            utils.Log.Errorf("API server shutdown error: %v", err)
        }
    }()

    utils.Log.Infof("API server started on port %d", port)
}