package main

import (
	"database/sql"
	"log"
	"os"
	"strings"
	"time"

	_ "github.com/lib/pq"
)

var DB *sql.DB

// InitDB initializes the database connection
func InitDB() {
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		dbURL = "postgresql://authclaw:authclaw@localhost:5432/authclaw?sslmode=disable"
	} else if !strings.Contains(dbURL, "sslmode") {
		if strings.Contains(dbURL, "?") {
			dbURL += "&sslmode=disable"
		} else {
			dbURL += "?sslmode=disable"
		}
	}

	var err error
	DB, err = sql.Open("postgres", dbURL)
	if err != nil {
		log.Fatalf("Failed to open database: %v", err)
	}

	if err = DB.Ping(); err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}

	maxOpenConns := envInt("GATEWAY_DB_MAX_OPEN_CONNS", 25)
	maxIdleConns := envInt("GATEWAY_DB_MAX_IDLE_CONNS", 10)
	connMaxLifetimeSeconds := envInt("GATEWAY_DB_CONN_MAX_LIFETIME_SECONDS", 300)
	DB.SetMaxOpenConns(maxOpenConns)
	DB.SetMaxIdleConns(maxIdleConns)
	DB.SetConnMaxLifetime(time.Duration(connMaxLifetimeSeconds) * time.Second)

	log.Printf("Database connection established successfully. pool_max_open=%d pool_max_idle=%d conn_max_lifetime_seconds=%d", maxOpenConns, maxIdleConns, connMaxLifetimeSeconds)
}
