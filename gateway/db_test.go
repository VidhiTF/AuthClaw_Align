package main

import (
	"context"
	"database/sql"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lib/pq"
)

func TestDatabaseTLSIntegration(t *testing.T) {
	positiveURL := os.Getenv("GATEWAY_DATABASE_TLS_TEST_URL")
	if positiveURL == "" {
		t.Skip("set GATEWAY_DATABASE_TLS_TEST_URL to run real PostgreSQL TLS evidence")
	}
	t.Setenv("AUTHCLAW_ENV", "production")
	open := func(raw string) (*sql.DB, error) {
		cfg, err := databaseConfig(raw)
		if err != nil {
			return nil, err
		}
		connector, err := pq.NewConnectorConfig(cfg)
		if err != nil {
			return nil, err
		}
		return sql.OpenDB(connector), nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	db, err := open(positiveURL)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var encrypted bool
	var protocol, cipher string
	if err := db.QueryRowContext(ctx, `SELECT ssl, COALESCE(version, ''), COALESCE(cipher, '') FROM pg_stat_ssl WHERE pid = pg_backend_pid()`).Scan(&encrypted, &protocol, &cipher); err != nil {
		t.Fatal(err)
	}
	if !encrypted || protocol == "" || cipher == "" {
		t.Fatalf("database transport not verified as TLS: ssl=%t protocol=%q cipher=%q", encrypted, protocol, cipher)
	}
	t.Logf("verified PostgreSQL transport: ssl=%t protocol=%s cipher=%s", encrypted, protocol, cipher)
	db.SetMaxIdleConns(0)
	if err := db.PingContext(ctx); err != nil {
		t.Fatalf("verified TLS reconnect failed: %v", err)
	}
	cancel()

	for _, tc := range []struct{ name, environment, expected string }{
		{"wrong hostname", "GATEWAY_DATABASE_TLS_WRONG_HOST_URL", "doesn't contain any ip sans"},
		{"untrusted CA", "GATEWAY_DATABASE_TLS_UNTRUSTED_CA_URL", "unknown authority"},
		{"expired cert", "GATEWAY_DATABASE_TLS_EXPIRED_CERT_URL", "certificate has expired"},
		{"missing CA", "GATEWAY_DATABASE_TLS_MISSING_CA_URL", "cannot find the file"},
		{"plaintext only", "GATEWAY_DATABASE_TLS_PLAINTEXT_URL", "ssl is not enabled"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := os.Getenv(tc.environment)
			if raw == "" {
				t.Fatalf("%s is required when TLS integration evidence is enabled", tc.environment)
			}
			rejected, openErr := open(raw)
			if openErr == nil {
				defer rejected.Close()
				caseCtx, caseCancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer caseCancel()
				openErr = rejected.PingContext(caseCtx)
			}
			if openErr == nil {
				t.Fatal("unsafe database TLS case connected successfully")
			}
			if !strings.Contains(strings.ToLower(openErr.Error()), tc.expected) {
				t.Fatalf("connection failed for the wrong reason: %v", openErr)
			}
			t.Logf("connection rejected: %v", openErr)
		})
	}
}

func TestInitDBAcceptsVerifiedTLS(t *testing.T) {
	const helper = "AUTHCLAW_T07_INIT_DB_TLS_HELPER"
	raw := os.Getenv("GATEWAY_DATABASE_TLS_INIT_URL")
	if raw == "" {
		t.Skip("set GATEWAY_DATABASE_TLS_INIT_URL to run real InitDB TLS evidence")
	}
	if os.Getenv(helper) == "1" {
		skipDatabaseSecurityValidationForTests = false
		InitDB()
		defer DB.Close()
		var encrypted bool
		if err := DB.QueryRow(`SELECT ssl FROM pg_stat_ssl WHERE pid = pg_backend_pid()`).Scan(&encrypted); err != nil || !encrypted {
			t.Fatalf("InitDB transport verification failed: ssl=%t err=%v", encrypted, err)
		}
		return
	}

	command := exec.Command(os.Args[0], "-test.run=^TestInitDBAcceptsVerifiedTLS$")
	command.Env = append(os.Environ(), helper+"=1", "AUTHCLAW_ENV=production", "DATABASE_URL="+raw)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("verified InitDB subprocess failed: %v\n%s", err, output)
	}
}

func TestInitDBRejectsUnsafeSharedDatabaseURL(t *testing.T) {
	const helper = "AUTHCLAW_T07_INIT_DB_HELPER"
	if os.Getenv(helper) == "1" {
		InitDB()
		return
	}

	const secretMarker = "T07_SECRET_MARKER"
	command := exec.Command(os.Args[0], "-test.run=^TestInitDBRejectsUnsafeSharedDatabaseURL$")
	command.Env = append(os.Environ(),
		helper+"=1",
		"AUTHCLAW_ENV=production",
		"DATABASE_URL=postgres://gateway:"+secretMarker+"@127.0.0.1:1/authclaw_gateway_test",
	)
	output, err := command.CombinedOutput()
	if err == nil {
		t.Fatal("gateway database initialization accepted a production URL without explicit verified TLS")
	}
	message := string(output)
	if !strings.Contains(message, "shared DATABASE_URL must use sslmode=verify-full") {
		t.Fatalf("unexpected startup rejection: %s", message)
	}
	if strings.Contains(message, secretMarker) {
		t.Fatal("startup rejection exposed database credentials")
	}
	if strings.Contains(strings.ToLower(message), "connect") {
		t.Fatalf("unsafe configuration reached a database connection attempt: %s", message)
	}
}

func TestDatabaseConfigTLS(t *testing.T) {
	for _, tc := range []struct {
		name, env, dsn string
		pgSSLMode      string
		mode           pq.SSLMode
		reject         bool
	}{
		{name: "production URL omission", env: "production", dsn: "postgres://user:sslmode-password@db/authclaw", reject: true},
		{name: "production keyword omission", env: "prod", dsn: "host=db user=app dbname=authclaw", reject: true},
		{name: "staging omission", env: "staging", dsn: "postgres://db/authclaw", reject: true},
		{name: "ci omission", env: "ci", dsn: "host=db", reject: true},
		{name: "inherited mode does not satisfy URL", env: "production", dsn: "postgres://db/authclaw", pgSSLMode: "verify-full", reject: true},
		{name: "inherited mode does not satisfy keyword DSN", env: "production", dsn: "host=db", pgSSLMode: "verify-full", reject: true},
		{name: "explicit URL verify full", env: "production", dsn: "postgres://db/authclaw?sslmode=verify-full", mode: pq.SSLModeVerifyFull},
		{name: "explicit URL verify full with query", env: "production", dsn: "postgres://db/authclaw?application_name=gateway&sslmode=verify-full", mode: pq.SSLModeVerifyFull},
		{name: "encoded URL key", env: "production", dsn: "postgres://db/authclaw?%73slmode=verify-full", mode: pq.SSLModeVerifyFull},
		{name: "explicit keyword verify full", env: "prod", dsn: "host=db user=app sslmode=verify-full dbname=authclaw", mode: pq.SSLModeVerifyFull},
		{name: "quoted keyword value", env: "production", dsn: "host=db password='contains sslmode=disable' sslmode=verify-full", mode: pq.SSLModeVerifyFull},
		{name: "escaped keyword value", env: "production", dsn: `host=db password=contains\ sslmode\=disable sslmode=verify-full`, mode: pq.SSLModeVerifyFull},
		{name: "multi host verify full", env: "production", dsn: "host=db-a,db-b port=5432,5432 sslmode=verify-full", mode: pq.SSLModeVerifyFull},
		{name: "reject duplicate URL modes", env: "production", dsn: "postgres://db/authclaw?sslmode=verify-full&sslmode=verify-full", reject: true},
		{name: "reject conflicting URL modes", env: "production", dsn: "postgres://db/authclaw?sslmode=disable&sslmode=verify-full", reject: true},
		{name: "reject duplicate keyword modes", env: "production", dsn: "host=db sslmode=verify-full sslmode=verify-full", reject: true},
		{name: "reject conflicting keyword modes", env: "production", dsn: "host=db sslmode=disable sslmode=verify-full", reject: true},
		{name: "reject empty URL mode", env: "production", dsn: "postgres://db/authclaw?sslmode=", reject: true},
		{name: "reject empty keyword mode", env: "production", dsn: "host=db sslmode=", reject: true},
		{name: "reject disabled", env: "production", dsn: "postgres://db/authclaw?sslmode=disable", reject: true},
		{name: "reject prefer", env: "prod", dsn: "host=db sslmode=prefer", reject: true},
		{name: "reject allow", env: "prod", dsn: "host=db sslmode=allow", reject: true},
		{name: "reject encryption only", env: "production", dsn: "host=db sslmode=require", reject: true},
		{name: "reject CA only", env: "production", dsn: "host=db sslmode=verify-ca", reject: true},
		{name: "reject unsupported mode", env: "production", dsn: "host=db sslmode=custom", reject: true},
		{name: "reject Unix socket", env: "production", dsn: "host=/var/run/postgresql sslmode=verify-full", reject: true},
		{name: "stage plaintext rejected", env: "stage", dsn: "host=db sslmode=disable", reject: true},
		{name: "shared missing rejected", env: "shared-test", dsn: "", reject: true},
		{name: "reject missing", env: "production", dsn: "", reject: true},
		{name: "local default", env: "local", dsn: "", mode: pq.SSLModeDisable},
		{name: "local URL default", env: "local", dsn: "postgres://db/authclaw", mode: pq.SSLModeDisable},
		{name: "invalid URL", env: "production", dsn: "postgres://user:secret@db:bad/authclaw", reject: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("AUTHCLAW_ENV", tc.env)
			if tc.pgSSLMode == "" {
				if err := os.Unsetenv("PGSSLMODE"); err != nil {
					t.Fatal(err)
				}
			} else {
				t.Setenv("PGSSLMODE", tc.pgSSLMode)
			}
			cfg, err := databaseConfig(tc.dsn)
			if (err != nil) != tc.reject {
				t.Fatalf("error=%v, want rejection=%v", err, tc.reject)
			}
			if err == nil && cfg.SSLMode != tc.mode {
				t.Fatalf("SSLMode=%q, want %q", cfg.SSLMode, tc.mode)
			}
		})
	}
}

func TestDatabaseConfigRejectsServiceFileTLSMode(t *testing.T) {
	serviceFile := filepath.Join(t.TempDir(), "pg_service.conf")
	if err := os.WriteFile(serviceFile, []byte("[t07]\nhost=db\nsslmode=verify-full\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AUTHCLAW_ENV", "production")
	t.Setenv("PGSERVICEFILE", serviceFile)
	if err := os.Unsetenv("PGSSLMODE"); err != nil {
		t.Fatal(err)
	}
	if _, err := databaseConfig("service=t07"); err == nil {
		t.Fatal("service-file sslmode must not satisfy the explicit DATABASE_URL contract")
	}
}

func TestCompatibleDatabaseRevisions(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		want    []string
		wantErr bool
	}{
		{name: "default", want: []string{"049"}},
		{name: "rollout window", value: "048, 049", want: []string{"048", "049"}},
		{name: "duplicate", value: "048,048", wantErr: true},
		{name: "malformed", value: "head", wantErr: true},
		{name: "unsupported", value: "046,047", wantErr: true},
		{name: "too broad", value: "046,047,048", wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.value == "" {
				t.Setenv("AUTHCLAW_EXPECTED_DB_REVISION", "")
			} else {
				t.Setenv("AUTHCLAW_EXPECTED_DB_REVISION", tc.value)
			}
			got, err := compatibleDatabaseRevisions()
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected an error")
				}
				return
			}
			if err != nil {
				t.Fatalf("compatibleDatabaseRevisions: %v", err)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
			for index := range got {
				if got[index] != tc.want[index] {
					t.Fatalf("got %v, want %v", got, tc.want)
				}
			}
		})
	}
}
