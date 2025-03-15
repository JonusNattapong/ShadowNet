package db

import (
	"context"
	"database/sql"
	"fmt"
	"shadownet/config"
	"shadownet/types"
	"shadownet/utils"

	_ "github.com/jackc/pgx/v5/stdlib"
)

// TestDatabase wraps a database connection for testing
type TestDatabase struct {
    DB *sql.DB
}

// NewTestDatabase creates a new test database instance
func NewTestDatabase() (*TestDatabase, error) {
    if err := InitTestDB(); err != nil {
        return nil, err
    }
    return &TestDatabase{DB: testDBInstance}, nil
}

// Close closes the test database connection
func (td *TestDatabase) Close() error {
    if td.DB != nil {
        return td.DB.Close()
    }
    return nil
}

// RecordAttack stores an attack in the database
func RecordAttack(db *sql.DB, attack types.Attack) (int64, error) {
    ctx := context.Background()
    result, err := db.ExecContext(ctx,
        `INSERT INTO attacks 
        (timestamp, ip_address, attack_type, details) 
        VALUES ($1, $2, $3, $4)`,
        attack.Timestamp,
        attack.SourceIP,
        attack.Type,
        attack.Details,
    )
    if err != nil {
        return 0, fmt.Errorf("failed to record attack: %v", err)
    }
    return result.LastInsertId()
}

var (
    dbInstance *sql.DB
    testDBInstance *sql.DB
)

// InitTestDB initializes an in-memory SQLite database for testing
func InitTestDB() error {
    db, err := sql.Open("sqlite3", ":memory:")
    if err != nil {
        return fmt.Errorf("failed to open test database: %v", err)
    }

    // Create tables
    ctx := context.Background()
    _, err = db.ExecContext(ctx, `
        CREATE TABLE attacks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            attack_type TEXT NOT NULL,
            ip_address TEXT NOT NULL,
            details TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            session_duration INTEGER DEFAULT 0
        )
    `)
    if err != nil {
        return fmt.Errorf("failed to create attacks table: %v", err)
    }

    _, err = db.ExecContext(ctx, `
        CREATE TABLE threat_intel (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT,
            reputation REAL,
            categories TEXT,
            last_updated DATETIME,
            source TEXT
        )
    `)
    if err != nil {
        return fmt.Errorf("failed to create threat_intel table: %v", err)
    }

    testDBInstance = db
    return nil
}

// GetTestDB returns the test database instance
func GetTestDB() *sql.DB {
    return testDBInstance
}

// GetDB returns the main database instance
func GetDB() *sql.DB {
    return dbInstance
}

// Connect initializes the database connection
func Connect() error {
    cfg, err := config.LoadConfig()
    if err != nil {
        return fmt.Errorf("failed to load config: %v", err)
    }

    var db *sql.DB
    
    // Use SQLite for testing if test_db is configured
    if cfg.Database.TestDB != "" {
        db, err = sql.Open("sqlite3", cfg.Database.TestDB)
    } else {
        // Use PostgreSQL for production
        connStr := fmt.Sprintf(
            "host=%s port=%d user=%s password=%s dbname=%s sslmode=disable",
            cfg.Database.Host,
            cfg.Database.Port,
            cfg.Database.User,
            cfg.Database.Password,
            cfg.Database.DBName,
        )
        db, err = sql.Open("pgx", connStr)
    }
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
func LogAttack(ip, attackType, details string) error {
    if dbInstance == nil {
        return fmt.Errorf("database connection not initialized")
    }

    ctx := context.Background()
    _, err := dbInstance.ExecContext(ctx,
        "INSERT INTO attacks (ip_address, attack_type, details, timestamp) VALUES ($1, $2, $3, CURRENT_TIMESTAMP)",
        ip, attackType, details,
    )
    if err != nil {
        return fmt.Errorf("failed to log attack: %v", err)
    }
    return nil
}

// GetLatestAttack retrieves the most recent attack from the database
func GetLatestAttack() (*types.Attack, error) {
    if dbInstance == nil {
        return nil, fmt.Errorf("database connection not initialized")
    }

    attack := &types.Attack{}
    err := dbInstance.QueryRow(`
        SELECT id, attack_type, ip_address, details, timestamp 
        FROM attacks 
        ORDER BY timestamp DESC 
        LIMIT 1
    `).Scan(&attack.ID, &attack.Type, &attack.SourceIP, &attack.Details, &attack.Timestamp)
    
    if err == sql.ErrNoRows {
        return nil, fmt.Errorf("no attacks found")
    }
    if err != nil {
        return nil, fmt.Errorf("failed to get latest attack: %v", err)
    }
    
    return attack, nil
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
            attack_type TEXT NOT NULL,
            ip_address TEXT NOT NULL,
            details TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            session_duration INTEGER DEFAULT 0
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
