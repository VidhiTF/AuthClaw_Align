package main

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"regexp"
	"strings"
	"time"

	_ "github.com/lib/pq"
)

var DB *sql.DB
var skipDatabaseSecurityValidationForTests bool

var databaseRevisionPattern = regexp.MustCompile(`^[0-9]{3}$`)
var rolloutDatabaseRevisions = map[string]struct{}{"046": {}, "047": {}}

func compatibleDatabaseRevisions() ([]string, error) {
	raw := os.Getenv("AUTHCLAW_EXPECTED_DB_REVISION")
	if raw == "" {
		raw = "047"
	}
	parts := strings.Split(raw, ",")
	revisions := make([]string, 0, len(parts))
	seen := make(map[string]struct{}, len(parts))
	for _, part := range parts {
		revision := strings.TrimSpace(part)
		if revision == "" || !databaseRevisionPattern.MatchString(revision) {
			return nil, fmt.Errorf("AUTHCLAW_EXPECTED_DB_REVISION contains an invalid revision")
		}
		if _, supported := rolloutDatabaseRevisions[revision]; !supported {
			return nil, fmt.Errorf("AUTHCLAW_EXPECTED_DB_REVISION contains an unsupported revision")
		}
		if _, exists := seen[revision]; exists {
			return nil, fmt.Errorf("AUTHCLAW_EXPECTED_DB_REVISION contains duplicate revisions")
		}
		seen[revision] = struct{}{}
		revisions = append(revisions, revision)
	}
	if len(revisions) == 0 || len(revisions) > 2 {
		return nil, fmt.Errorf("AUTHCLAW_EXPECTED_DB_REVISION must contain one or two revisions")
	}
	return revisions, nil
}

// ValidateDatabaseSecurity refuses startup against a stale or insecure database.
func ValidateDatabaseSecurity() error {
	expectedRevisions, err := compatibleDatabaseRevisions()
	if err != nil {
		return err
	}
	rows, err := DB.Query(`SELECT version_num FROM public.alembic_version`)
	if err != nil {
		return fmt.Errorf("database revision validation query failed: %w", err)
	}
	defer rows.Close()
	actualRevisions := make([]string, 0, 1)
	for rows.Next() {
		var revision string
		if err := rows.Scan(&revision); err != nil {
			return fmt.Errorf("database revision validation scan failed: %w", err)
		}
		actualRevisions = append(actualRevisions, revision)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("database revision validation failed: %w", err)
	}
	if len(actualRevisions) != 1 {
		return fmt.Errorf("database security validation failed: expected one migration head")
	}
	compatible := false
	for _, expected := range expectedRevisions {
		if actualRevisions[0] == expected {
			compatible = true
			break
		}
	}
	if !compatible {
		return fmt.Errorf(
			"database security validation failed: migration head %q is not compatible",
			actualRevisions[0],
		)
	}

	var secure bool
	err = DB.QueryRow(`
		SELECT
			EXISTS (
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
