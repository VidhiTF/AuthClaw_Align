package main

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	_ "github.com/lib/pq"
)

var DB *sql.DB
var skipDatabaseSecurityValidationForTests bool

// ValidateDatabaseSecurity refuses startup against a stale or insecure database.
func ValidateDatabaseSecurity() error {
	var secure bool
	err := DB.QueryRow(`
		SELECT
			EXISTS (SELECT 1 FROM public.alembic_version WHERE version_num = '041')
			AND EXISTS (
				SELECT 1
				FROM pg_proc p
				JOIN pg_namespace n ON n.oid = p.pronamespace
				JOIN pg_roles r ON r.oid = p.proowner
				WHERE n.nspname = 'authn'
				  AND p.proname IN ('bind_session_context', 'bind_api_key_context')
				  AND p.prosecdef
				  AND r.rolname = 'authclaw_auth_definer'
				  AND NOT EXISTS (
					SELECT 1
					FROM aclexplode(COALESCE(p.proacl, acldefault('f', p.proowner))) acl
					WHERE acl.grantee = 0 AND acl.privilege_type = 'EXECUTE'
				  )
				GROUP BY n.nspname
				HAVING count(*) = 2
			)
			AND NOT EXISTS (
				SELECT 1 FROM pg_roles
				WHERE rolname = current_user AND (rolsuper OR rolbypassrls)
			)
			AND NOT EXISTS (
				SELECT 1
				FROM pg_class c
				JOIN pg_namespace n ON n.oid = c.relnamespace
				WHERE n.nspname = 'public' AND c.relkind = 'r'
				  AND EXISTS (
					SELECT 1 FROM pg_attribute a
					WHERE a.attrelid = c.oid AND a.attname = 'tenant_id' AND NOT a.attisdropped
				  )
				  AND (NOT c.relrowsecurity OR NOT c.relforcerowsecurity)
			)
	`).Scan(&secure)
	if err != nil {
		return fmt.Errorf("database security validation query failed: %w", err)
	}
	if !secure {
		return fmt.Errorf("database security validation failed")
	}
	return nil
}

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

	if !skipDatabaseSecurityValidationForTests {
		err = ValidateDatabaseSecurity()
	}
	if err != nil {
		log.Fatalf("Refusing startup: %v", err)
	}

	maxOpenConns := envInt("GATEWAY_DB_MAX_OPEN_CONNS", 25)
	maxIdleConns := envInt("GATEWAY_DB_MAX_IDLE_CONNS", 10)
	connMaxLifetimeSeconds := envInt("GATEWAY_DB_CONN_MAX_LIFETIME_SECONDS", 300)
	DB.SetMaxOpenConns(maxOpenConns)
	DB.SetMaxIdleConns(maxIdleConns)
	DB.SetConnMaxLifetime(time.Duration(connMaxLifetimeSeconds) * time.Second)

	log.Printf("Database connection established successfully. pool_max_open=%d pool_max_idle=%d conn_max_lifetime_seconds=%d", maxOpenConns, maxIdleConns, connMaxLifetimeSeconds)
}
