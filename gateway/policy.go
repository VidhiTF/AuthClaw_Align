package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/redis/go-redis/v9"
	"gopkg.in/yaml.v3"
)

// Redis connection client
var RedisClient *redis.Client

func InitRedis() {
	redisURL := os.Getenv("REDIS_URL")
	if redisURL == "" {
		redisURL = "localhost:6379"
	}
	if strings.HasPrefix(redisURL, "redis://") || strings.HasPrefix(redisURL, "rediss://") {
		opts, err := redis.ParseURL(redisURL)
		if err == nil {
			RedisClient = redis.NewClient(opts)
			return
		}
		log.Printf("Invalid REDIS_URL %q, falling back to raw address: %v", redisURL, err)
	}
	RedisClient = redis.NewClient(&redis.Options{Addr: redisURL})
}

// Policy definitions
type ModelRules struct {
	Whitelist []string `yaml:"whitelist" json:"whitelist"`
	Blacklist []string `yaml:"blacklist" json:"blacklist"`
}

type RegexRule struct {
	Name               string `yaml:"name" json:"name"`
	Pattern            string `yaml:"pattern" json:"pattern"`
	Reason             string `yaml:"reason" json:"reason"`
	Action             string `yaml:"action" json:"action"`
	Severity           string `yaml:"severity" json:"severity"`
	Entity             string `yaml:"entity" json:"entity"`
	HITLTimeoutSeconds int    `yaml:"hitl_timeout_seconds" json:"hitl_timeout_seconds"`
}

type TopicRule struct {
	Topic         string   `yaml:"topic" json:"topic"`
	AllowedModels []string `yaml:"allowed_models" json:"allowed_models"`
	Reason        string   `yaml:"reason" json:"reason"`
}

type RateLimits struct {
	RequestsPerMinute int `yaml:"requests_per_minute" json:"requests_per_minute"`
}

type PolicyConfig struct {
	ModelRules ModelRules  `yaml:"model_rules" json:"model_rules"`
	RegexRules []RegexRule `yaml:"regex_rules" json:"regex_rules"`
	TopicRules []TopicRule `yaml:"topic_rules" json:"topic_rules"`
	RateLimits RateLimits  `yaml:"rate_limits" json:"rate_limits"`
}

// Thread-safe in-memory cache with TTL
type CachedPolicy struct {
	Policy    *PolicyConfig
	PolicyID  string
	ExpiredAt time.Time
}

type cachedPolicyDecision struct {
	Allow     bool
	Reason    string
	PolicyID  string
	ExpiresAt time.Time
}

var (
	policyCache           = make(map[string]CachedPolicy)
	policyCacheMu         sync.RWMutex
	policyDecisionCache   sync.Map
	policyBlockTotal      atomic.Uint64
	policyWarnTotal       atomic.Uint64
	policyRedactTotal     atomic.Uint64
	policyFailClosedTotal atomic.Uint64
)

func GetCachedPolicy(tenantID string) (*PolicyConfig, string, bool) {
	policyCacheMu.RLock()
	defer policyCacheMu.RUnlock()

	cached, exists := policyCache[tenantID]
	if !exists || time.Now().After(cached.ExpiredAt) {
		return nil, "", false
	}
	return cached.Policy, cached.PolicyID, true
}

func SetCachedPolicy(tenantID string, policy *PolicyConfig, policyID string, ttl time.Duration) {
	policyCacheMu.Lock()
	defer policyCacheMu.Unlock()

	policyCache[tenantID] = CachedPolicy{
		Policy:    policy,
		PolicyID:  policyID,
		ExpiredAt: time.Now().Add(ttl),
	}
}

func InvalidatePolicyCache(tenantID string) {
	policyCacheMu.Lock()
	defer policyCacheMu.Unlock()
	delete(policyCache, tenantID)
}

func policyDecisionCacheTTL() time.Duration {
	return time.Duration(envInt("GATEWAY_POLICY_DECISION_CACHE_TTL_MS", 0)) * time.Millisecond
}

func policyDecisionCacheKey(tenantID, model, route string, prompts []string, topics []string) string {
	payload, _ := json.Marshal([]interface{}{tenantID, model, route, prompts, topics})
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

func getCachedPolicyDecision(key string) (cachedPolicyDecision, bool) {
	raw, ok := policyDecisionCache.Load(key)
	if !ok {
		return cachedPolicyDecision{}, false
	}
	cached, ok := raw.(cachedPolicyDecision)
	if !ok || time.Now().After(cached.ExpiresAt) {
		policyDecisionCache.Delete(key)
		return cachedPolicyDecision{}, false
	}
	return cached, true
}

func setCachedPolicyDecision(key string, decision cachedPolicyDecision) {
	ttl := policyDecisionCacheTTL()
	if ttl <= 0 {
		return
	}
	decision.ExpiresAt = time.Now().Add(ttl)
	policyDecisionCache.Store(key, decision)
}

// ValidatePolicyYAML parses YAML and compiles regexes to reject malformed policies
func ValidatePolicyYAML(yamlStr string) (*PolicyConfig, error) {
	var config PolicyConfig
	if err := yaml.Unmarshal([]byte(yamlStr), &config); err != nil {
		return nil, fmt.Errorf("invalid YAML syntax: %w", err)
	}

	for idx, rule := range config.RegexRules {
		if strings.TrimSpace(rule.Pattern) == "" {
			return nil, fmt.Errorf("regex rule %d missing pattern", idx)
		}
		if _, err := regexp.Compile(rule.Pattern); err != nil {
			return nil, fmt.Errorf("invalid regex pattern '%s': %w", rule.Pattern, err)
		}
		action := strings.ToLower(strings.TrimSpace(rule.Action))
		switch action {
		case "", "redact", "warn", "require_approval", "block":
		default:
			return nil, fmt.Errorf("invalid regex rule action '%s' for rule '%s'", rule.Action, rule.Name)
		}
		if action == "require_approval" && (rule.HITLTimeoutSeconds < 0 || rule.HITLTimeoutSeconds > 1800 || (rule.HITLTimeoutSeconds > 0 && rule.HITLTimeoutSeconds < 10)) {
			return nil, fmt.Errorf("regex rule '%s' hitl_timeout_seconds must be between 10 and 1800 seconds", rule.Name)
		}
	}

	for idx, rule := range config.TopicRules {
		if strings.TrimSpace(rule.Topic) == "" {
			return nil, fmt.Errorf("topic rule %d missing topic", idx)
		}
		if len(rule.AllowedModels) == 0 {
			return nil, fmt.Errorf("topic rule '%s' must include at least one allowed model", rule.Topic)
		}
	}

	return &config, nil
}

type ApprovalRuleMatch struct {
	Rule        RegexRule
	PromptIndex int
	MatchHash   string
}

func (r RegexRule) normalizedAction() string {
	action := strings.ToLower(strings.TrimSpace(r.Action))
	if action == "" {
		return "redact"
	}
	return action
}

func FindRegexRuleMatchByAction(config *PolicyConfig, prompts []string, action string) (*ApprovalRuleMatch, error) {
	if config == nil {
		return nil, nil
	}
	for _, rule := range config.RegexRules {
		if rule.normalizedAction() != action {
			continue
		}
		re, err := regexp.Compile(rule.Pattern)
		if err != nil {
			return nil, err
		}
		for idx, prompt := range prompts {
			match := re.FindString(prompt)
			if match == "" {
				continue
			}
			hash := sha256.Sum256([]byte(match))
			return &ApprovalRuleMatch{
				Rule:        rule,
				PromptIndex: idx,
				MatchHash:   hex.EncodeToString(hash[:]),
			}, nil
		}
	}
	return nil, nil
}

func FindApprovalRuleMatch(config *PolicyConfig, prompts []string) (*ApprovalRuleMatch, error) {
	return FindRegexRuleMatchByAction(config, prompts, "require_approval")
}

func FindBlockingRuleMatch(config *PolicyConfig, prompts []string) (*ApprovalRuleMatch, error) {
	return FindRegexRuleMatchByAction(config, prompts, "block")
}

func FindWarningRuleMatch(config *PolicyConfig, prompts []string) (*ApprovalRuleMatch, error) {
	return FindRegexRuleMatchByAction(config, prompts, "warn")
}

func RedactionRulesForEgress(config *PolicyConfig) []RegexRule {
	if config == nil {
		return nil
	}
	rules := make([]RegexRule, 0, len(config.RegexRules))
	for _, rule := range config.RegexRules {
		switch rule.normalizedAction() {
		case "redact", "warn", "require_approval":
			rules = append(rules, rule)
		}
	}
	return rules
}

func safePolicyAuditLabel(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	var normalized strings.Builder
	for _, char := range value {
		switch {
		case char >= 'a' && char <= 'z':
			normalized.WriteRune(char)
		case char >= '0' && char <= '9':
			normalized.WriteRune(char)
		case char == '-' || char == '_':
			normalized.WriteRune(char)
		case char == ' ':
			normalized.WriteByte('_')
		}
		if normalized.Len() >= 64 {
			break
		}
	}
	if normalized.Len() == 0 {
		return "sensitive"
	}
	return normalized.String()
}

func PolicyRuleAuditTrace(match *ApprovalRuleMatch, action string) []string {
	if match == nil {
		return []string{"action=" + safePolicyAuditLabel(action)}
	}
	entity := match.Rule.Entity
	if strings.TrimSpace(entity) == "" {
		entity = match.Rule.Name
	}
	return []string{
		"action=" + safePolicyAuditLabel(action),
		"entity=" + safePolicyAuditLabel(entity),
		"match_sha256=" + match.MatchHash,
	}
}

func RecordPolicyAction(action string) {
	switch strings.ToLower(strings.TrimSpace(action)) {
	case "block":
		policyBlockTotal.Add(1)
	case "warn":
		policyWarnTotal.Add(1)
	case "redact":
		policyRedactTotal.Add(1)
	case "fail_closed":
		policyFailClosedTotal.Add(1)
	}
}

func PolicyActionMetricsSnapshot() map[string]uint64 {
	return map[string]uint64{
		"authclaw_gateway_policy_block_total":       policyBlockTotal.Load(),
		"authclaw_gateway_policy_warn_total":        policyWarnTotal.Load(),
		"authclaw_gateway_policy_redact_total":      policyRedactTotal.Load(),
		"authclaw_gateway_policy_fail_closed_total": policyFailClosedTotal.Load(),
	}
}

func PolicyRuleDecisionReason(match *ApprovalRuleMatch, action string) string {
	if match == nil {
		return fmt.Sprintf("Policy rule action %s matched", action)
	}
	ruleName := strings.TrimSpace(match.Rule.Name)
	if ruleName == "" {
		ruleName = "unnamed_rule"
	}
	reason := strings.TrimSpace(match.Rule.Reason)
	if reason == "" {
		reason = fmt.Sprintf("Rule %s matched", ruleName)
	}
	return fmt.Sprintf("Policy rule %q action=%s matched: %s", ruleName, action, reason)
}

// LoadPolicyWithCache handles loading from cache, fallback to Postgres under RLS
func LoadPolicyWithCache(ctx context.Context, tenantID string) (*PolicyConfig, string, error) {
	if tenantID == "" {
		return nil, "", nil
	}

	// 1. Check cache
	if config, policyID, ok := GetCachedPolicy(tenantID); ok {
		return config, policyID, nil
	}

	// 2. Query Postgres under Tenant RLS context
	var policyID string
	var policyYAML string

	err := RunInTenantTx(ctx, tenantID, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx,
			"SELECT id, policy_yaml FROM policies WHERE tenant_id = $1 AND is_active = true ORDER BY version DESC LIMIT 1",
			tenantID,
		).Scan(&policyID, &policyYAML)
	})

	if err == sql.ErrNoRows {
		// Cache negative lookup (empty policy) for 30 seconds
		SetCachedPolicy(tenantID, nil, "", 30*time.Second)
		return nil, "", nil
	}
	if err != nil {
		return nil, "", fmt.Errorf("failed to fetch policy from database: %w", err)
	}

	// 3. Parse and validate YAML
	config, err := ValidatePolicyYAML(policyYAML)
	if err != nil {
		return nil, "", fmt.Errorf("policy validation failed: %w", err)
	}

	// 4. Update Cache
	SetCachedPolicy(tenantID, config, policyID, 30*time.Second)

	return config, policyID, nil
}

// CheckRateLimit implements sliding/fixed window rate limit per tenant + route
func CheckRateLimit(ctx context.Context, tenantID, route string, limit int) (bool, error) {
	if RedisClient == nil {
		InitRedis()
	}
	if limit <= 0 {
		return false, nil
	}

	now := time.Now().Format("200601021504")
	key := fmt.Sprintf("rate_limit:%s:%s:%s", tenantID, route, now)

	pipe := RedisClient.Pipeline()
	incr := pipe.Incr(ctx, key)
	pipe.Expire(ctx, key, 60*time.Second)

	_, err := pipe.Exec(ctx)
	if err != nil {
		return false, err
	}

	count := incr.Val()
	if count > int64(limit) {
		return true, nil
	}
	return false, nil
}

// OPA JSON Request / Response payloads
type OPAPayload struct {
	Input struct {
		TenantID          string        `json:"tenant_id"`
		Model             string        `json:"model"`
		Prompts           []string      `json:"prompts"`
		Topics            []string      `json:"topics"`
		RateLimitExceeded bool          `json:"rate_limit_exceeded"`
		Policy            *PolicyConfig `json:"policy,omitempty"`
	} `json:"input"`
}

type OPAResponse struct {
	Result struct {
		Allow  bool   `json:"allow"`
		Reason string `json:"reason"`
	} `json:"result"`
}

func opaRequestTimeout() time.Duration {
	timeoutMs := envInt("OPA_TIMEOUT_MS", 5000)
	if timeoutMs < 100 {
		timeoutMs = 100
	}
	if timeoutMs > 30000 {
		timeoutMs = 30000
	}
	return time.Duration(timeoutMs) * time.Millisecond
}

func inStringSlice(items []string, value string) bool {
	for _, item := range items {
		if item == value {
			return true
		}
	}
	return false
}

func evaluatePolicyLocal(config *PolicyConfig, model string, prompts []string, topics []string, rateLimitExceeded bool) (bool, string, error) {
	if rateLimitExceeded {
		return false, "Rate limit exceeded", nil
	}
	if config == nil {
		return true, "Allowed by local policy", nil
	}
	if inStringSlice(config.ModelRules.Blacklist, model) {
		return false, fmt.Sprintf("Model '%s' is blacklisted", model), nil
	}
	if len(config.ModelRules.Whitelist) > 0 && !inStringSlice(config.ModelRules.Whitelist, model) {
		return false, fmt.Sprintf("Model '%s' is not in whitelist", model), nil
	}
	if match, err := FindBlockingRuleMatch(config, prompts); err != nil {
		return false, "", err
	} else if match != nil {
		return false, PolicyRuleDecisionReason(match, "block"), nil
	}
	for _, rule := range config.TopicRules {
		for _, topic := range topics {
			if rule.Topic == topic && !inStringSlice(rule.AllowedModels, model) {
				return false, "Topic block: " + rule.Reason, nil
			}
		}
	}
	return true, "Allowed by local policy", nil
}

// EvaluatePolicy evaluates rules against OPA. Uses strict DEFAULT-DENY on failure.
func EvaluatePolicy(ctx context.Context, tenantID, model, route string, prompts []string, topics []string) (bool, string, string, error) {
	if tenantID == "" {
		return true, "Allowed (no tenant context)", "", nil
	}

	// Default-deny values on any failure
	defaultDenyReason := "Request blocked: policy evaluation failure (default-deny)"

	// 1. Load Policy (caches results, enforces RLS)
	config, policyID, err := LoadPolicyWithCache(ctx, tenantID)
	if err != nil {
		log.Printf("[POLICY-ERROR] LoadPolicy failed for tenant %s: %v", tenantID, err)
		return false, "Request blocked: policy loading or parsing error", "", err
	}
	decisionCacheKey := ""
	if config == nil || config.RateLimits.RequestsPerMinute <= 0 {
		decisionCacheKey = policyDecisionCacheKey(tenantID, model, route, prompts, topics)
		if cached, ok := getCachedPolicyDecision(decisionCacheKey); ok {
			return cached.Allow, cached.Reason, cached.PolicyID, nil
		}
	}

	// 2. Check tenant + route rate limiting in Redis
	rateLimitExceeded := false
	if config != nil && config.RateLimits.RequestsPerMinute > 0 {
		var limitErr error
		rateLimitExceeded, limitErr = CheckRateLimit(ctx, tenantID, route, config.RateLimits.RequestsPerMinute)
		if limitErr != nil {
			log.Printf("[POLICY-ERROR] Rate limiting check failed for tenant %s: %v", tenantID, limitErr)
			return false, "Request blocked: rate limiting check failure", policyID, limitErr
		}
	}

	if envBool("GATEWAY_POLICY_LOCAL_FAST_PATH", false) {
		allow, reason, err := evaluatePolicyLocal(config, model, prompts, topics, rateLimitExceeded)
		if err != nil {
			return false, defaultDenyReason, policyID, err
		}
		return allow, reason, policyID, nil
	}

	// 3. Build OPA input payload
	var payload OPAPayload
	payload.Input.TenantID = tenantID
	payload.Input.Model = model
	payload.Input.Prompts = prompts
	payload.Input.Topics = topics
	payload.Input.RateLimitExceeded = rateLimitExceeded
	payload.Input.Policy = config

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		log.Printf("[POLICY-ERROR] Marshal OPA payload failed: %v", err)
		return false, defaultDenyReason, policyID, err
	}

	// 4. Query OPA REST API
	opaURL := os.Getenv("OPA_URL")
	if opaURL == "" {
		opaURL = "http://localhost:8181"
	}

	req, err := http.NewRequestWithContext(ctx, "POST", opaURL+"/v1/data/authclaw", bytes.NewBuffer(payloadBytes))
	if err != nil {
		log.Printf("[POLICY-ERROR] Create OPA request failed: %v", err)
		return false, defaultDenyReason, policyID, err
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: opaRequestTimeout()}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("[POLICY-ERROR] OPA query failed (service unavailable): %v", err)
		return false, "Request blocked: policy evaluation engine unavailable", policyID, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		log.Printf("[POLICY-ERROR] OPA returned status %d: %s", resp.StatusCode, string(body))
		return false, defaultDenyReason, policyID, fmt.Errorf("OPA status error: %d", resp.StatusCode)
	}

	var opaResp OPAResponse
	if err := json.NewDecoder(resp.Body).Decode(&opaResp); err != nil {
		log.Printf("[POLICY-ERROR] Decode OPA response failed: %v", err)
		return false, defaultDenyReason, policyID, err
	}

	if opaResp.Result.Reason == "" {
		if opaResp.Result.Allow {
			opaResp.Result.Reason = "Allowed by OPA policy"
		} else {
			opaResp.Result.Reason = defaultDenyReason
		}
	}

	if decisionCacheKey != "" {
		setCachedPolicyDecision(decisionCacheKey, cachedPolicyDecision{
			Allow:    opaResp.Result.Allow,
			Reason:   opaResp.Result.Reason,
			PolicyID: policyID,
		})
	}
	return opaResp.Result.Allow, opaResp.Result.Reason, policyID, nil
}
