package main

import (
	"os"
	"testing"

	"github.com/lib/pq"
)

func TestDatabaseConfigTLS(t *testing.T) {
	t.Setenv("PGSSLMODE", "")
	if err := os.Unsetenv("PGSSLMODE"); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, env, dsn string
		mode           pq.SSLMode
		reject         bool
	}{
		{"production default", "production", "postgres://user:sslmode-password@db/authclaw", pq.SSLModeVerifyFull, false},
		{"prod alias keyword DSN", "prod", "host=db user=app dbname=authclaw", pq.SSLModeVerifyFull, false},
		{"explicit verify full", "production", "postgres://db/authclaw?sslmode=verify-full", pq.SSLModeVerifyFull, false},
		{"reject disabled", "production", "postgres://db/authclaw?sslmode=disable", "", true},
		{"reject prefer", "prod", "host=db sslmode=prefer", "", true},
		{"reject allow", "prod", "host=db sslmode=allow", "", true},
		{"reject encryption only", "production", "host=db sslmode=require", "", true},
		{"reject CA only", "production", "host=db sslmode=verify-ca", "", true},
		{"staging default", "staging", "postgres://db/authclaw", pq.SSLModeVerifyFull, false},
		{"stage plaintext rejected", "stage", "host=db sslmode=disable", "", true},
		{"shared missing rejected", "shared-test", "", "", true},
		{"ci default", "ci", "host=db", pq.SSLModeVerifyFull, false},
		{"reject missing", "production", "", "", true},
		{"local default", "local", "", pq.SSLModeDisable, false},
		{"local URL default", "local", "postgres://db/authclaw", pq.SSLModeDisable, false},
		{"invalid URL", "production", "postgres://user:secret@db:bad/authclaw", "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("AUTHCLAW_ENV", tc.env)
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

func TestCompatibleDatabaseRevisions(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		want    []string
		wantErr bool
	}{
		{name: "default", want: []string{"047"}},
		{name: "rollout window", value: "046, 047", want: []string{"046", "047"}},
		{name: "duplicate", value: "047,047", wantErr: true},
		{name: "malformed", value: "head", wantErr: true},
		{name: "unsupported", value: "047,048", wantErr: true},
		{name: "too broad", value: "045,046,047", wantErr: true},
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
