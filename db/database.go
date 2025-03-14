package db

import (
	"database/sql"
	"fmt"
	"shadownet/config"

	_ "github.com/jackc/pgx/v4/stdlib"
)

var dbInstance *sql.DB

// Connect initializes the database
func Connect() {
    cfg := config.LoadConfig()
    connStr := fmt.Sprintf(
        "host=%s port=%d user=%s password=%s dbname=%s sslmode=disable",
        cfg.Database.Host,
        cfg.Database.Port,
        cfg.Database.User,
        cfg.Database.Password,
        cfg.Database.DBName,
    )
    db, _ := sql.Open("pgx", connStr)
    dbInstance = db
    Migrate()
}

// LogAttack records attack attempts
func LogAttack(username, password, service string) {
    dbInstance.Exec(
        "INSERT INTO attacks (username, password, service) VALUES ($1, $2, $3)",
        username, password, service,
    )
}