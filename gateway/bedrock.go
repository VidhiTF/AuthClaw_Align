package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

// This file handles everything specific to AWS Bedrock:
// AWS SigV4 signing, usage limits, and request/response helpers.

// isBedrockEnabled returns true only when both master flags are explicitly set.
func isBedrockEnabled() bool {
	aws := strings.ToLower(os.Getenv("AWS_ENABLED"))
	bdr := strings.ToLower(os.Getenv("BEDROCK_ENABLED"))
	return aws == "true" && bdr == "true"
}

func hmacSHA256(key []byte, data string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(data))
	return h.Sum(nil)
}

func sha256Hex(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

// SignBedrockRequest applies AWS SigV4 signing to an outbound HTTP request.
// Reads credentials exclusively from environment variables.
// Modifies the Authorization and x-amz-* headers in-place.
func SignBedrockRequest(req *http.Request, bodyBytes []byte) error {
	accessKey := os.Getenv("AWS_ACCESS_KEY_ID")
	secretKey := os.Getenv("AWS_SECRET_ACCESS_KEY")
	region := os.Getenv("AWS_REGION")
	if region == "" {
		region = "us-east-1"
	}

	if accessKey == "" || secretKey == "" {
		return fmt.Errorf(
			"AWS credentials not configured: set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY in .env.local",
		)
	}

	service := "bedrock"
	now := time.Now().UTC()
	amzDate := now.Format("20060102T150405Z")
	dateStamp := now.Format("20060102")

	// ── Step 1: Canonical request ─────────────────────────────────────────────
	bodyHash := sha256Hex(bodyBytes)

	host := req.URL.Host
	if host == "" {
		host = req.Host
	}

	req.Header.Set("host", host)
	req.Header.Set("x-amz-date", amzDate)
	req.Header.Set("x-amz-content-sha256", bodyHash)

	// Canonical headers (sorted lowercase)
	canonicalHeaders := fmt.Sprintf(
		"host:%s\nx-amz-content-sha256:%s\nx-amz-date:%s\n",
		host, bodyHash, amzDate,
	)
	signedHeaders := "host;x-amz-content-sha256;x-amz-date"

	canonicalURI := req.URL.Path
	if canonicalURI == "" {
		canonicalURI = "/"
	}

	canonicalRequest := strings.Join([]string{
		req.Method,
		canonicalURI,
		req.URL.RawQuery,
		canonicalHeaders,
		signedHeaders,
		bodyHash,
	}, "\n")

	// ── Step 2: String to sign ────────────────────────────────────────────────
	credentialScope := fmt.Sprintf("%s/%s/%s/aws4_request", dateStamp, region, service)
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256",
		amzDate,
		credentialScope,
		sha256Hex([]byte(canonicalRequest)),
	}, "\n")

	// ── Step 3: Derived signing key ───────────────────────────────────────────
	kDate := hmacSHA256([]byte("AWS4"+secretKey), dateStamp)
	kRegion := hmacSHA256(kDate, region)
	kService := hmacSHA256(kRegion, service)
	kSigning := hmacSHA256(kService, "aws4_request")
	signature := hex.EncodeToString(hmacSHA256(kSigning, stringToSign))

	// ── Step 4: Authorization header ─────────────────────────────────────────
	authHeader := fmt.Sprintf(
		"AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		accessKey, credentialScope, signedHeaders, signature,
	)
	req.Header.Set("Authorization", authHeader)

	return nil
}

// CheckBedrockUsageLimits reads current usage from Postgres for the tenant.
// Returns non-nil error if any hard limit is exceeded; nil means safe to proceed.
// This is called BEFORE the reverse proxy forwards the request to Bedrock.
func CheckBedrockUsageLimits(ctx context.Context, tenantID string) error {
	var (
		dailyRequests    int
		maxDailyRequests int
		dailyTokens      int
		maxDailyTokens   int
		dailyCost        float64
		maxDailyCost     float64
		lastReset        time.Time
		found            bool
	)

	err := RunInTenantTx(ctx, tenantID, func(tx *sql.Tx) error {
		row := tx.QueryRowContext(ctx,
			`SELECT daily_requests, max_daily_requests,
			        daily_tokens,   max_daily_tokens,
			        daily_cost_estimate, max_daily_cost_usd,
			        last_reset
			 FROM aws_usage_limits
			 WHERE tenant_id = $1 LIMIT 1`,
			tenantID,
		)
		err := row.Scan(
			&dailyRequests, &maxDailyRequests,
			&dailyTokens, &maxDailyTokens,
			&dailyCost, &maxDailyCost,
			&lastReset,
		)
		if err == sql.ErrNoRows {
			found = false
			return nil
		}
		if err != nil {
			return err
		}
		found = true
		return nil
	})

	if err != nil {
		// DB error: fail-safe — log and allow rather than blocking all traffic
		log.Printf("[BEDROCK-LIMIT] DB read error for tenant %s: %v — allowing request", tenantID, err)
		return nil
	}

	if !found {
		// No row yet — first Bedrock call for this tenant; limits haven't been hit
		return nil
	}

	// ── Day rollover check ────────────────────────────────────────────────────
	now := time.Now().UTC()
	if now.Format("2006-01-02") != lastReset.UTC().Format("2006-01-02") {
		// New calendar day — reset counters and allow this request
		ResetBedrockDailyCounters(ctx, tenantID)
		return nil
	}

	// ── Hard limit checks ─────────────────────────────────────────────────────
	if dailyRequests >= maxDailyRequests {
		return fmt.Errorf(
			"bedrock_limit_exceeded: daily request limit reached (%d/%d). Resets tomorrow UTC.",
			dailyRequests, maxDailyRequests,
		)
	}
	if dailyTokens >= maxDailyTokens {
		return fmt.Errorf(
			"bedrock_limit_exceeded: daily token limit reached (%d/%d). Resets tomorrow UTC.",
			dailyTokens, maxDailyTokens,
		)
	}
	if dailyCost >= maxDailyCost {
		return fmt.Errorf(
			"bedrock_limit_exceeded: daily cost ceiling reached ($%.4f/$%.4f). Resets tomorrow UTC.",
			dailyCost, maxDailyCost,
		)
	}

	return nil
}

// IncrementBedrockUsage atomically increments request and token counters.
// Called AFTER a successful Bedrock response. Best-effort — failures are logged only.
func IncrementBedrockUsage(ctx context.Context, tenantID string, estimatedTokens int) {
	// Estimate cost at Claude Haiku rate: ~$0.25 per 1M input tokens
	costEstimate := float64(estimatedTokens) * 0.00000025

	maxReq, _ := strconv.Atoi(os.Getenv("BEDROCK_MAX_REQUESTS_PER_DAY"))
	if maxReq == 0 {
		maxReq = 100
	}
	maxTok, _ := strconv.Atoi(os.Getenv("BEDROCK_MAX_TOKENS_PER_DAY"))
	if maxTok == 0 {
		maxTok = 50000
	}
	maxCost, _ := strconv.ParseFloat(os.Getenv("BEDROCK_MAX_COST_ESTIMATE_USD"), 64)
	if maxCost == 0 {
		maxCost = 1.0
	}

	if DB == nil {
		return
	}
	_, err := DB.ExecContext(ctx,
		`INSERT INTO aws_usage_limits
		     (tenant_id, daily_requests, daily_tokens, daily_cost_estimate,
		      max_daily_requests, max_daily_tokens, max_daily_cost_usd,
		      last_reset, updated_at)
		 VALUES ($1, 1, $2, $3, $4, $5, $6, NOW(), NOW())
		 ON CONFLICT (tenant_id) DO UPDATE SET
		     daily_requests      = aws_usage_limits.daily_requests + 1,
		     daily_tokens        = aws_usage_limits.daily_tokens + $2,
		     daily_cost_estimate = aws_usage_limits.daily_cost_estimate + $3,
		     updated_at          = NOW()`,
		tenantID, estimatedTokens, costEstimate, maxReq, maxTok, maxCost,
	)
	if err != nil {
		log.Printf("[BEDROCK-USAGE] Failed to increment usage for tenant %s: %v", tenantID, err)
	}
}

// ResetBedrockDailyCounters zeroes daily counters for a new UTC calendar day.
func ResetBedrockDailyCounters(ctx context.Context, tenantID string) {
	if DB == nil {
		return
	}
	_, err := DB.ExecContext(ctx,
		`UPDATE aws_usage_limits
		 SET daily_requests = 0, daily_tokens = 0, daily_cost_estimate = 0,
		     last_reset = NOW(), updated_at = NOW()
		 WHERE tenant_id = $1`,
		tenantID,
	)
	if err != nil {
		log.Printf("[BEDROCK-USAGE] Failed to reset counters for tenant %s: %v", tenantID, err)
	}
}

// BedrockEndpoint constructs the Bedrock runtime endpoint URL.
func BedrockEndpoint() string {
	explicit := os.Getenv("AWS_BEDROCK_ENDPOINT")
	if explicit != "" {
		return strings.TrimRight(explicit, "/")
	}
	region := os.Getenv("AWS_REGION")
	if region == "" {
		region = "us-east-1"
	}
	return fmt.Sprintf("https://bedrock-runtime.%s.amazonaws.com", region)
}

// ExtractBedrockModel extracts the model ID from a Bedrock invoke path.
// Bedrock path: /model/{modelId}/invoke  or  /bedrock/model/{modelId}/invoke
func ExtractBedrockModel(path string) string {
	path = strings.TrimPrefix(path, "/bedrock")
	parts := strings.Split(path, "/model/")
	if len(parts) < 2 {
		return ""
	}
	return strings.Split(parts[1], "/")[0]
}

// BedrockTokensFromBody estimates token usage from a Claude/Bedrock JSON response.
// Claude responses include: {"usage": {"input_tokens": N, "output_tokens": N}}
// Returns 0 if parsing fails (non-fatal — cost estimate only).
func BedrockTokensFromBody(body []byte) int {
	var resp struct {
		Usage struct {
			InputTokens  int `json:"input_tokens"`
			OutputTokens int `json:"output_tokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return 0
	}
	return resp.Usage.InputTokens + resp.Usage.OutputTokens
}

// ReadAndEstimateBedrockTokens reads the full response body, estimates token count,
// and returns the body bytes so the proxy can forward them.
func ReadAndEstimateBedrockTokens(r io.Reader) (tokens int, body []byte, err error) {
	body, err = io.ReadAll(r)
	if err != nil {
		return 0, nil, err
	}
	tokens = BedrockTokensFromBody(body)
	return tokens, body, nil
}
