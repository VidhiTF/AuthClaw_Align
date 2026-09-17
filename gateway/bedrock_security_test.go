package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

const budgetModel = "anthropic.claude-3-haiku-20240307-v1:0"

func TestProviderQuotaPrecedesAndShortCircuitsBedrockBudget(t *testing.T) {
	var order []string
	allowed := admitProviderResources(func() bool {
		order = append(order, "quota")
		return false
	}, func() bool {
		order = append(order, "budget")
		return true
	})
	if allowed || len(order) != 1 || order[0] != "quota" {
		t.Fatalf("denied provider quota reached budget admission: allowed=%v order=%v", allowed, order)
	}

	order = nil
	allowed = admitProviderResources(func() bool {
		order = append(order, "quota")
		return true
	}, func() bool {
		order = append(order, "budget")
		return true
	})
	if !allowed || strings.Join(order, ",") != "quota,budget" {
		t.Fatalf("admission order=%v allowed=%v", order, allowed)
	}
}

func testBedrockBudget(t *testing.T, tenant string, requests, tokens int, cost float64) {
	t.Helper()
	t.Setenv("AWS_ENABLED", "true")
	t.Setenv("BEDROCK_ENABLED", "true")
	raw, err := json.Marshal(map[string]bedrockTenantBudget{tenant: {
		Models: map[string]bedrockModelBudget{budgetModel: {1000, 20, 1, 2}}, Requests: requests, Tokens: tokens, Cost: cost,
	}})
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("BEDROCK_TENANTS_JSON", string(raw))
}
func TestBedrockEntitlementDeniesUnknownTenantAndModel(t *testing.T) {
	testBedrockBudget(t, "allowed", 3, 5000, 1)
	for _, pair := range [][2]string{{"", budgetModel}, {"other", budgetModel}, {"allowed", "other-model"}} {
		if _, _, err := bedrockEntitlement(pair[0], pair[1]); err == nil {
			t.Fatalf("allowed %v", pair)
		}
	}
	if _, _, err := bedrockEntitlement("allowed", budgetModel); err != nil {
		t.Fatal(err)
	}
	t.Setenv("BEDROCK_TENANTS_JSON", `{"allowed":{"models":{}}}`)
	if _, _, err := bedrockEntitlement("allowed", budgetModel); err == nil {
		t.Fatal("incomplete entitlement accepted")
	}
	t.Setenv("BEDROCK_ENABLED", "false")
	if _, _, err := bedrockEntitlement("allowed", budgetModel); err == nil {
		t.Fatal("disabled feature accepted")
	}
}
func TestBedrockReservationIncludesInputCeilingAndOutput(t *testing.T) {
	price := bedrockModelBudget{1000, 20, 1, 2}
	for _, body := range []string{`{"max_tokens":10}`, `{"textGenerationConfig":{"maxTokenCount":10}}`} {
		tokens, cost, err := bedrockReservation([]byte(body), price)
		if err != nil || tokens != 1010 || cost != 0.0011 {
			t.Fatalf("tokens=%d cost=%v err=%v", tokens, cost, err)
		}
	}
	for _, body := range []string{`{}`, `{"max_tokens":-1}`, `{"max_tokens":21}`, `{"max_tokens":1.5}`} {
		if _, _, err := bedrockReservation([]byte(body), price); err == nil {
			t.Fatalf("accepted %s", body)
		}
	}
}
func TestBedrockBudgetFailsClosedWithoutDatabase(t *testing.T) {
	testBedrockBudget(t, "tenant", 3, 5000, 1)
	previous := DB
	DB = nil
	defer func() { DB = previous }()
	if err := ReserveBedrockUsage(context.Background(), "tenant", budgetModel, []byte(`{"max_tokens":10}`)); err == nil {
		t.Fatal("missing database allowed egress")
	}
}
func TestBedrockSigningUsesSessionTokenAndTrustedEndpoint(t *testing.T) {
	t.Setenv("AWS_REGION", "us-east-1")
	t.Setenv("AWS_ACCESS_KEY_ID", "synthetic-access")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "synthetic-secret")
	t.Setenv("AWS_SESSION_TOKEN", "synthetic-session")
	t.Setenv("AWS_CONFIG_FILE", t.TempDir()+"/absent")
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", t.TempDir()+"/absent")
	req := httptest.NewRequest("POST", "https://bedrock-runtime.us-east-1.amazonaws.com/model/test/invoke", strings.NewReader(`{}`))
	req.Header.Set("X-Amz-Security-Token", "client-token")
	req.Header.Set("Authorization", "client-authorization")
	if err := SignBedrockRequest(req, []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	if req.Header.Get("X-Amz-Security-Token") != "synthetic-session" || !strings.HasPrefix(req.Header.Get("Authorization"), "AWS4-HMAC-SHA256 ") {
		t.Fatal("temporary credentials were not signed")
	}
	for _, target := range []string{"http://bedrock-runtime.us-east-1.amazonaws.com", "https://attacker.invalid", "https://bedrock-runtime.us-west-2.amazonaws.com"} {
		req := httptest.NewRequest("POST", target, nil)
		if err := SignBedrockRequest(req, nil); err == nil {
			t.Fatalf("signed untrusted endpoint %s", target)
		}
	}
}

type recordingBedrockTransport struct{ calls int }

func (transport *recordingBedrockTransport) RoundTrip(*http.Request) (*http.Response, error) {
	transport.calls++
	return nil, fmt.Errorf("unexpected egress")
}
func TestBedrockSigningFailureNeverForwards(t *testing.T) {
	upstream := &recordingBedrockTransport{}
	req := httptest.NewRequest("POST", "https://untrusted.invalid", strings.NewReader(`{}`))
	if _, err := (bedrockSigningTransport{upstream}).RoundTrip(req); err == nil || upstream.calls != 0 {
		t.Fatal("signing failure forwarded request")
	}
}
func TestBedrockBudgetAuthenticatedPostgres(t *testing.T) {
	raw := os.Getenv("BEDROCK_TEST_OWNER_DATABASE_URL")
	if raw == "" {
		t.Skip("requires disposable PostgreSQL")
	}
	open := func(raw string) *sql.DB {
		parsed, err := url.Parse(raw)
		if err != nil || !strings.HasSuffix(parsed.Path, "_test") || (parsed.Hostname() != "127.0.0.1" && parsed.Hostname() != "localhost") {
			t.Fatal("requires loopback disposable test database")
		}
		q := parsed.Query()
		q.Set("sslmode", "disable")
		parsed.RawQuery = q.Encode()
		db, err := sql.Open("postgres", parsed.String())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { db.Close() })
		return db
	}
	owner, app := open(raw), open(os.Getenv("DATABASE_URL"))
	previous, skip := DB, skipDatabaseSecurityValidationForTests
	DB, skipDatabaseSecurityValidationForTests = app, false
	defer func() { DB, skipDatabaseSecurityValidationForTests = previous, skip }()
	for _, test := range []struct {
		name             string
		requests, tokens int
		cost             float64
		admitted         int
	}{
		{"request ceiling", 3, 5000, 1, 3}, {"token ceiling", 10, 2020, 1, 2}, {"cost ceiling", 10, 10000, 0.0022, 2},
	} {
		t.Run(test.name, func(t *testing.T) {
			tenant, user, key := randomTestUUID(t), randomTestUUID(t), randomTestUUID(t)
			hash := strings.ReplaceAll(randomTestUUID(t), "-", "") + strings.ReplaceAll(randomTestUUID(t), "-", "")
			for _, fixture := range []struct {
				query string
				args  []any
			}{
				{`INSERT INTO tenants(id,name,status) VALUES ($1,$2,'active')`, []any{tenant, "budget regression " + tenant}},
				{`INSERT INTO users(id,tenant_id,email,role,platform_role,is_active) VALUES ($1,$2,$3,'admin','NONE',true)`, []any{user, tenant, user + "@example.invalid"}},
				{`INSERT INTO api_keys(id,tenant_id,key_hash,name,created_by) VALUES ($1,$2,$3,'budget-regression',$4)`, []any{key, tenant, hash, user}},
			} {
				if _, err := owner.Exec(fixture.query, fixture.args...); err != nil {
					t.Fatal(err)
				}
			}
			testBedrockBudget(t, tenant, test.requests, test.tokens, test.cost)
			ctx := context.WithValue(context.Background(), APIKeyHashContextKey, hash)
			ctx = context.WithValue(ctx, CredentialKindContextKey, "api_key")
			body := []byte(`{"max_tokens":10}`)
			var accepted atomic.Int64
			failures := make(chan error, 24)
			var group sync.WaitGroup
			for range 24 {
				group.Go(func() {
					if err := ReserveBedrockUsage(ctx, tenant, budgetModel, body); err == nil {
						accepted.Add(1)
					} else {
						failures <- err
					}
				})
			}
			group.Wait()
			close(failures)
			if int(accepted.Load()) != test.admitted {
				t.Fatalf("admitted %d want %d; first failure: %v", accepted.Load(), test.admitted, <-failures)
			}
			var requests, tokens int
			if err := owner.QueryRow(`SELECT daily_requests,daily_tokens FROM aws_usage_limits WHERE tenant_id=$1`, tenant).Scan(&requests, &tokens); err != nil {
				t.Fatal(err)
			}
			if requests != test.admitted || tokens != test.admitted*1010 {
				t.Fatalf("persisted %d requests/%d tokens", requests, tokens)
			}
			if err := ReserveBedrockUsage(context.Background(), tenant, budgetModel, body); err == nil {
				t.Fatal("unbound tenant wrote budget")
			}
			if _, err := owner.Exec(`UPDATE aws_usage_limits SET last_reset=now()-interval '1 day' WHERE tenant_id=$1`, tenant); err != nil {
				t.Fatal(err)
			}
			if err := ReserveBedrockUsage(ctx, tenant, budgetModel, body); err != nil {
				t.Fatal("UTC rollover failed:", err)
			}
			// A newer-day row may be committed while an older transaction waits for its lock.
			if _, err := owner.Exec(`UPDATE aws_usage_limits SET last_reset=now()+interval '1 day',daily_requests=max_daily_requests WHERE tenant_id=$1`, tenant); err != nil {
				t.Fatal(err)
			}
			if err := ReserveBedrockUsage(ctx, tenant, budgetModel, body); err == nil {
				t.Fatal("older transaction reset a newer day's budget")
			}

		})
	}
}

func TestBedrockChinaEndpoint(t *testing.T) {
	t.Setenv("AWS_REGION", "cn-north-1")
	t.Setenv("AWS_BEDROCK_ENDPOINT", "")
	if BedrockEndpoint() != "https://bedrock-runtime.cn-north-1.amazonaws.com.cn" {
		t.Fatal("China endpoint mismatch")
	}
}

func TestBedrockSigningRejectsUnpricedInvocationOverrides(t *testing.T) {
	t.Setenv("AWS_REGION", "us-east-1")
	for _, header := range []string{"X-Amzn-Bedrock-Service-Tier", "X-Amzn-Bedrock-PerformanceConfig-Latency", "X-Amzn-Bedrock-GuardrailIdentifier"} {
		req := httptest.NewRequest("POST", "https://bedrock-runtime.us-east-1.amazonaws.com/model/test/invoke", nil)
		req.Header.Set(header, "unsupported")
		if err := SignBedrockRequest(req, nil); err == nil {
			t.Fatal("accepted unpriced invocation override:", header)
		}
	}
}
