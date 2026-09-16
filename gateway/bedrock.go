package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/config"
)

func isBedrockEnabled() bool {
	return strings.EqualFold(os.Getenv("AWS_ENABLED"), "true") && strings.EqualFold(os.Getenv("BEDROCK_ENABLED"), "true")
}

type bedrockModelBudget struct {
	// Trusted operator-supplied full model input ceiling, not a client token estimate.
	MaxInputTokens  int     `json:"max_input_tokens"`
	MaxOutputTokens int     `json:"max_output_tokens"`
	InputPrice      float64 `json:"input_usd_per_million"`
	OutputPrice     float64 `json:"output_usd_per_million"`
}
type bedrockTenantBudget struct {
	Models   map[string]bedrockModelBudget `json:"models"`
	Requests int                           `json:"max_daily_requests"`
	Tokens   int                           `json:"max_daily_tokens"`
	Cost     float64                       `json:"max_daily_cost_usd"`
}

var bedrockBudgets struct {
	sync.Mutex
	raw     string
	tenants map[string]bedrockTenantBudget
	err     error
}

func bedrockEntitlement(tenant, model string) (bedrockTenantBudget, bedrockModelBudget, error) {
	var budget bedrockTenantBudget
	var price bedrockModelBudget
	if tenant == "" || !isBedrockEnabled() {
		return budget, price, fmt.Errorf("Bedrock is not enabled for this tenant")
	}
	raw := os.Getenv("BEDROCK_TENANTS_JSON")
	bedrockBudgets.Lock()
	defer bedrockBudgets.Unlock()
	if raw != bedrockBudgets.raw || bedrockBudgets.tenants == nil {
		bedrockBudgets.raw, bedrockBudgets.tenants = raw, nil
		bedrockBudgets.err = json.Unmarshal([]byte(raw), &bedrockBudgets.tenants)
	}
	budget = bedrockBudgets.tenants[tenant]
	price, allowed := budget.Models[model]
	if bedrockBudgets.err != nil || !allowed || budget.Requests <= 0 || budget.Requests > 1000000000 ||
		budget.Tokens <= 0 || budget.Tokens > 1000000000 || !finitePositive(budget.Cost, 999999) ||
		price.MaxInputTokens <= 0 || price.MaxInputTokens > 10000000 || price.MaxOutputTokens <= 0 ||
		price.MaxOutputTokens > 10000000 || !finitePositive(price.InputPrice, 1000000) || !finitePositive(price.OutputPrice, 1000000) {
		return budget, price, fmt.Errorf("Bedrock tenant/model entitlement or budget is missing or invalid")
	}
	return budget, price, nil
}
func finitePositive(value, ceiling float64) bool {
	return value > 0 && value <= ceiling && !math.IsNaN(value) && !math.IsInf(value, 0)
}

func bedrockReservation(body []byte, price bedrockModelBudget) (int, float64, error) {
	var request struct {
		MaxTokens  int `json:"max_tokens"`
		Generation struct {
			MaxTokens int `json:"maxTokenCount"`
		} `json:"textGenerationConfig"`
	}
	if err := json.Unmarshal(body, &request); err != nil {
		return 0, 0, fmt.Errorf("invalid Bedrock output limit")
	}
	output := request.MaxTokens
	if output == 0 {
		output = request.Generation.MaxTokens
	}
	if output <= 0 || output > price.MaxOutputTokens {
		return 0, 0, fmt.Errorf("Bedrock output limit is missing or exceeds entitlement")
	}
	// Reserve the entire configured model input ceiling plus bounded output; no optimistic refunds.
	cost := math.Ceil((float64(price.MaxInputTokens)*price.InputPrice+float64(output)*price.OutputPrice)/100) / 10000
	return price.MaxInputTokens + output, cost, nil
}

// Atomic admission and UTC rollover execute under the caller's authenticated tenant context.
// Every request, including failed egress, retains its conservative reservation until rollover.
// A transaction that began before midnight must never reset a newer day after waiting on a row lock.
func ReserveBedrockUsage(ctx context.Context, tenant, model string, body []byte) error {
	budget, price, err := bedrockEntitlement(tenant, model)
	if err != nil {
		return err
	}
	tokens, cost, err := bedrockReservation(body, price)
	if err != nil {
		return err
	}
	if DB == nil {
		return fmt.Errorf("Bedrock budget storage is unavailable")
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	err = RunInTenantTx(ctx, tenant, func(tx *sql.Tx) error {
		var admitted int
		return tx.QueryRowContext(ctx, `
            INSERT INTO aws_usage_limits (tenant_id, daily_requests, daily_tokens, daily_cost_estimate,
                max_daily_requests, max_daily_tokens, max_daily_cost_usd, last_reset, updated_at)
            SELECT $1::uuid, 1, $2::integer, $3::numeric, $4::integer, $5::integer, $6::numeric, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP
            WHERE $2::integer <= $5::integer AND $3::numeric <= $6::numeric
            ON CONFLICT (tenant_id) DO UPDATE SET
                daily_requests = CASE WHEN (aws_usage_limits.last_reset AT TIME ZONE 'UTC')::date >= (CURRENT_TIMESTAMP AT TIME ZONE 'UTC')::date THEN aws_usage_limits.daily_requests + 1 ELSE 1 END,
                daily_tokens = CASE WHEN (aws_usage_limits.last_reset AT TIME ZONE 'UTC')::date >= (CURRENT_TIMESTAMP AT TIME ZONE 'UTC')::date THEN aws_usage_limits.daily_tokens + $2::integer ELSE $2::integer END,
                daily_cost_estimate = CASE WHEN (aws_usage_limits.last_reset AT TIME ZONE 'UTC')::date >= (CURRENT_TIMESTAMP AT TIME ZONE 'UTC')::date THEN aws_usage_limits.daily_cost_estimate + $3::numeric ELSE $3::numeric END,
                max_daily_requests=$4::integer, max_daily_tokens=$5::integer, max_daily_cost_usd=$6::numeric,
                last_reset=GREATEST(aws_usage_limits.last_reset, CURRENT_TIMESTAMP), updated_at=CURRENT_TIMESTAMP
            WHERE (CASE WHEN (aws_usage_limits.last_reset AT TIME ZONE 'UTC')::date >= (CURRENT_TIMESTAMP AT TIME ZONE 'UTC')::date THEN aws_usage_limits.daily_requests ELSE 0 END) < $4::integer
              AND (CASE WHEN (aws_usage_limits.last_reset AT TIME ZONE 'UTC')::date >= (CURRENT_TIMESTAMP AT TIME ZONE 'UTC')::date THEN aws_usage_limits.daily_tokens ELSE 0 END) <= $5::integer - $2::integer
              AND (CASE WHEN (aws_usage_limits.last_reset AT TIME ZONE 'UTC')::date >= (CURRENT_TIMESTAMP AT TIME ZONE 'UTC')::date THEN aws_usage_limits.daily_cost_estimate ELSE 0 END) <= $6::numeric - $3::numeric
            RETURNING daily_requests`, tenant, tokens, fmt.Sprintf("%.4f", cost), budget.Requests, budget.Tokens,
			fmt.Sprintf("%.4f", math.Floor(budget.Cost*10000)/10000)).Scan(&admitted)
	})
	if err != nil {
		return fmt.Errorf("Bedrock budget unavailable or exhausted: %w", err)
	}
	return nil
}

var bedrockAWSCredentials struct {
	sync.Mutex
	region   string
	provider aws.CredentialsProvider
}

func bedrockCredentials(ctx context.Context, region string) (aws.Credentials, error) {
	bedrockAWSCredentials.Lock()
	if bedrockAWSCredentials.provider == nil || bedrockAWSCredentials.region != region {
		cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
		if err != nil {
			bedrockAWSCredentials.Unlock()
			return aws.Credentials{}, err
		}
		bedrockAWSCredentials.provider, bedrockAWSCredentials.region = cfg.Credentials, region
	}
	provider := bedrockAWSCredentials.provider
	bedrockAWSCredentials.Unlock()
	return provider.Retrieve(ctx)
}

// The SDK handles canonical signing, temporary session tokens, and renewable task/role credentials.
func SignBedrockRequest(req *http.Request, body []byte) error {
	region := os.Getenv("AWS_REGION")
	if region == "" {
		region = "us-east-1"
	}
	suffix := ".amazonaws.com"
	if strings.HasPrefix(region, "cn-") {
		suffix += ".cn"
	}
	if req.URL.Scheme != "https" || req.URL.Host != "bedrock-runtime."+region+suffix || req.URL.User != nil || req.URL.RawQuery != "" {
		return fmt.Errorf("Bedrock signing requires the regional HTTPS runtime endpoint")
	}
	for key := range req.Header {
		if strings.HasPrefix(strings.ToLower(key), "x-amzn-") {
			return fmt.Errorf("Bedrock invocation overrides are not supported")
		}
	}
	ctx, cancel := context.WithTimeout(req.Context(), 5*time.Second)
	defer cancel()
	creds, err := bedrockCredentials(ctx, region)
	if err != nil {
		return fmt.Errorf("Bedrock signing credentials unavailable")
	}
	// Client-supplied signing headers must never be incorporated into the AWS signature.
	for key := range req.Header {
		if strings.HasPrefix(strings.ToLower(key), "x-amz-") {
			req.Header.Del(key)
		}
	}
	req.Header.Del("Authorization")
	req.Header.Set("X-Amzn-Bedrock-PerformanceConfig-Latency", "standard")
	req.Header.Set("X-Amzn-Bedrock-Service-Tier", "default")
	return v4.NewSigner().SignHTTP(ctx, creds, req, fmt.Sprintf("%x", sha256.Sum256(body)), "bedrock", region, time.Now())
}

type bedrockSigningTransport struct{ http.RoundTripper }

func (transport bedrockSigningTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Body == nil {
		return nil, fmt.Errorf("Bedrock request body is required")
	}
	body, err := io.ReadAll(io.LimitReader(req.Body, 4*1024*1024+1))
	req.Body.Close()
	if err != nil || len(body) > 4*1024*1024 {
		return nil, fmt.Errorf("Bedrock signing body unavailable or too large")
	}
	signed := req.Clone(req.Context())
	signed.Body = io.NopCloser(bytes.NewReader(body))
	if err = SignBedrockRequest(signed, body); err != nil {
		return nil, err
	}
	return transport.RoundTripper.RoundTrip(signed)
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
	endpoint := fmt.Sprintf("https://bedrock-runtime.%s.amazonaws.com", region)
	if strings.HasPrefix(region, "cn-") {
		endpoint += ".cn"
	}
	return endpoint
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
