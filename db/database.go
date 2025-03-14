package db

import (
	"context"
	"database/sql"
	"fmt"
	"shadownet/config"
	"shadownet/utils"

	_ "github.com/jackc/pgx/v5/stdlib"
)

var dbInstance *sql.DB

// Connect initializes the database connection
func Connect() error {
    cfg, err := config.LoadConfig()
    if err != nil {
        return fmt.Errorf("failed to load config: %v", err)
    }

    connStr := fmt.Sprintf(
        "host=%s port=%d user=%s password=%s dbname=%s sslmode=disable",
        cfg.Database.Host,
        cfg.Database.Port,
        cfg.Database.User,
        cfg.Database.Password,
        cfg.Database.DBName,
    )

    db, err := sql.Open("pgx", connStr)
    if err != nil {
        return fmt.Errorf("failed to open database: %v", err)
    }

    // Test the connection
    ctx := context.Background()
    if err := db.PingContext(ctx); err != nil {
        db.Close()
        return fmt.Errorf("failed to ping database: %v", err)
    }

    dbInstance = db

    // Run migrations
    if err := Migrate(); err != nil {
        db.Close()
        return fmt.Errorf("failed to run migrations: %v", err)
    }

    utils.Log.Info("Database connection established successfully")
    return nil
}

// LogAttack records attack attempts with proper error handling
func LogAttack(ip, credential, service string) {
    if dbInstance == nil {
        utils.Log.Error("Database connection not initialized")
        return
    }

    ctx := context.Background()
    _, err := dbInstance.ExecContext(ctx,
        "INSERT INTO attacks (ip_address, credential, service, timestamp) VALUES ($1, $2, $3, CURRENT_TIMESTAMP)",
        ip, credential, service,
    )
    if err != nil {
        utils.Log.Errorf("Failed to log attack: %v", err)
    }
}

// Close closes the database connection
func Close() error {
    if dbInstance != nil {
        if err := dbInstance.Close(); err != nil {
            return fmt.Errorf("failed to close database connection: %v", err)
        }
        dbInstance = nil
    }
    return nil
}

// Migrate runs database migrations
func Migrate() error {
    if dbInstance == nil {
        return fmt.Errorf("database connection not initialized")
    }

    ctx := context.Background()
    
    // Create attacks table if it doesn't exist
    _, err := dbInstance.ExecContext(ctx, `
        CREATE TABLE IF NOT EXISTS attacks (
            id SERIAL PRIMARY KEY,
            ip_address TEXT,
            credential TEXT,
            service TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            attack_vector TEXT,
            payload BYTEA,
            session_duration INTEGER
        )
    `)
    if err != nil {
        return fmt.Errorf("failed to create attacks table: %v", err)
    }

    // Create threat_intel table if it doesn't exist
    _, err = dbInstance.ExecContext(ctx, `
        CREATE TABLE IF NOT EXISTS threat_intel (
            id SERIAL PRIMARY KEY,
            ip_address TEXT,
            reputation FLOAT,
            categories TEXT[],
            last_updated TIMESTAMP,
            source TEXT
        )
    `)
    if err != nil {
        return fmt.Errorf("failed to create threat_intel table: %v", err)
    }

    return nil
}