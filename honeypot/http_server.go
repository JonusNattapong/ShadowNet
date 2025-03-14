package honeypot

import (
	"context"
	"fmt"
	"net/http"
	"shadownet/db"
	"shadownet/utils"
	"strings"
)

// HTTPServer implements a fake HTTP server
type HTTPServer struct {
    BaseHoneypot
}

// StartHTTPServer starts a fake HTTP server with proper error handling
func StartHTTPServer(port int) error {
    httpServer := &HTTPServer{
        BaseHoneypot: BaseHoneypot{
            Name: "HTTP",
            Port: port,
        },
    }

    // Create HTTP server
    server := &http.Server{
        Addr: fmt.Sprintf(":%d", port),
        Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            // Extract real IP address
            ip := r.RemoteAddr
            if idx := strings.LastIndex(ip, ":"); idx != -1 {
                ip = ip[:idx]
            }
            if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
                ip = forwarded
            }

            // Log the attack details
            attackData := fmt.Sprintf("%s %s %s\nUser-Agent: %s\nReferer: %s",
                r.Method,
                r.URL.String(),
                r.Proto,
                r.UserAgent(),
                r.Referer(),
            )

            utils.Log.Warningf("HTTP attack attempt from %s: %s %s",
                ip, r.Method, r.URL.String())

            // Log to database
            db.LogAttack(ip, attackData, "http")

            // Send a generic response
            w.Header().Set("Server", "Apache/2.4.41 (Ubuntu)")
            w.Header().Set("Content-Type", "text/html")
            w.WriteHeader(http.StatusOK)
            w.Write([]byte("<html><body><h1>It works!</h1></body></html>"))
        }),
    }

    // Initialize the base honeypot
    if err := httpServer.Initialize(port); err != nil {
        return err
    }

    // Create a context for graceful shutdown
    ctx, cancel := context.WithCancel(context.Background())
    defer cancel()

    go func() {
        utils.Log.Infof("HTTP honeypot running on port %d", port)
        if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
            utils.Log.Errorf("HTTP server error: %v", err)
        }
    }()

    // Handle graceful shutdown
    go func() {
        <-ctx.Done()
        shutdownCtx, cancel := context.WithTimeout(context.Background(), httpServer.Timeout)
        defer cancel()
        
        if err := server.Shutdown(shutdownCtx); err != nil {
            utils.Log.Errorf("Error shutting down HTTP server: %v", err)
        }
    }()

    return nil
}