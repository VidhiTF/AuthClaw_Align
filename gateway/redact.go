package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Context keys
type contextKeyType string

const RequestTokenMapKey contextKeyType = "request_token_map"

// Presidio structures
type PresidioClient struct {
	BaseURL string
}

type PresidioPattern struct {
	Name  string  `json:"name"`
	Regex string  `json:"regex"`
	Score float64 `json:"score"`
}

type PresidioRecognizer struct {
	Name              string            `json:"name"`
	SupportedLanguage string            `json:"supported_language"`
	Patterns          []PresidioPattern `json:"patterns"`
	SupportedEntity   string            `json:"supported_entity"`
}

type AnalyzeRequest struct {
	Text             string               `json:"text"`
	Language         string               `json:"language"`
	AdHocRecognizers []PresidioRecognizer `json:"ad_hoc_recognizers,omitempty"`
	Entities         []string             `json:"entities,omitempty"`
}

type AnalyzeResult struct {
	Start      int     `json:"start"`
	End        int     `json:"end"`
	EntityType string  `json:"entity_type"`
	Score      float64 `json:"score"`
}

type CustomNERRecognizerConfig struct {
	Name            string   `json:"name"`
	EntityType      string   `json:"entity_type"`
	Patterns        []string `json:"patterns"`
	ContextKeywords []string `json:"context_keywords,omitempty"`
	Score           float64  `json:"score,omitempty"`
}

type RedactionRuntimeConfig struct {
	Strategy           string
	TokenRetentionDays int
}

func NewPresidioClient() *PresidioClient {
	url := os.Getenv("PRESIDIO_URL")
	if url == "" {
		url = "http://localhost:3000"
	}
	return &PresidioClient{BaseURL: url}
}

var presidioClientHTTP = &http.Client{
	Transport: &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 100,
		IdleConnTimeout:     90 * time.Second,
	},
	Timeout: 10 * time.Second,
}

var (
	presidioLimiterOnce  sync.Once
	presidioLimiter      chan struct{}
	presidioOfflineUntil sync.Map
	redactionTokenCache  sync.Map

	redactionAnalyzeRequestsTotal  atomic.Uint64
	redactionPresidioSuccessTotal  atomic.Uint64
	redactionPresidioFallbackTotal atomic.Uint64
	redactionPresidioTimeoutTotal  atomic.Uint64
	redactionPresidioSlowTotal     atomic.Uint64
	redactionEntitiesTotal         atomic.Uint64
	redactionTokensCreatedTotal    atomic.Uint64
	redactionTokensReusedTotal     atomic.Uint64
	redactionTokensPurgedTotal     atomic.Uint64
)

func envDurationMillis(name string, fallback time.Duration, min time.Duration, max time.Duration) time.Duration {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return fallback
	}
	ms, err := strconv.Atoi(raw)
	if err != nil {
		return fallback
	}
	value := time.Duration(ms) * time.Millisecond
	if value < min {
		return min
	}
	if value > max {
		return max
	}
	return value
}

func presidioAnalyzeTimeout() time.Duration {
	return envDurationMillis("PRESIDIO_ANALYZE_TIMEOUT_MS", 750*time.Millisecond, 25*time.Millisecond, 10*time.Second)
}

func presidioFailureCooldown() time.Duration {
	return envDurationMillis("PRESIDIO_FAILURE_COOLDOWN_MS", 5*time.Second, 0, time.Minute)
}

func presidioSlowLogThreshold() time.Duration {
	return envDurationMillis("PRESIDIO_SLOW_LOG_MS", 500*time.Millisecond, 100*time.Millisecond, 10*time.Second)
}

func envBoundedInt(name string, fallback, min, max int) int {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return fallback
	}
	value, err := strconv.Atoi(raw)
	if err != nil {
		return fallback
	}
	if value < min {
		return min
	}
	if value > max {
		return max
	}
	return value
}

func presidioMaxConcurrency() int {
	return envBoundedInt("PRESIDIO_MAX_CONCURRENCY", 10, 1, 200)
}

func presidioAcquireTimeout() time.Duration {
	return envDurationMillis("PRESIDIO_ACQUIRE_TIMEOUT_MS", 100*time.Millisecond, 10*time.Millisecond, 5*time.Second)
}

func redactionTokenCacheTTL() time.Duration {
	return envDurationMillis("REDACTION_TOKEN_CACHE_TTL_MS", 30*time.Second, 0, 10*time.Minute)
}

func acquirePresidioSlot(ctx context.Context) (func(), bool) {
	presidioLimiterOnce.Do(func() {
		presidioLimiter = make(chan struct{}, presidioMaxConcurrency())
	})
	timer := time.NewTimer(presidioAcquireTimeout())
	defer timer.Stop()
	select {
	case presidioLimiter <- struct{}{}:
		return func() { <-presidioLimiter }, true
	case <-timer.C:
		return nil, false
	case <-ctx.Done():
		return nil, false
	}
}

func presidioIsOffline(baseURL string) bool {
	raw, ok := presidioOfflineUntil.Load(baseURL)
	if !ok {
		return false
	}
	until, ok := raw.(time.Time)
	if !ok || time.Now().After(until) {
		presidioOfflineUntil.Delete(baseURL)
		return false
	}
	return true
}

func markPresidioFailure(baseURL string) {
	cooldown := presidioFailureCooldown()
	if cooldown <= 0 {
		return
	}
	presidioOfflineUntil.Store(baseURL, time.Now().Add(cooldown))
}

func markPresidioSuccess(baseURL string) {
	presidioOfflineUntil.Delete(baseURL)
}

func RedactionMetricsSnapshot() map[string]uint64 {
	return map[string]uint64{
		"authclaw_gateway_redaction_analyze_requests_total":  redactionAnalyzeRequestsTotal.Load(),
		"authclaw_gateway_redaction_presidio_success_total":  redactionPresidioSuccessTotal.Load(),
		"authclaw_gateway_redaction_presidio_fallback_total": redactionPresidioFallbackTotal.Load(),
		"authclaw_gateway_redaction_presidio_timeout_total":  redactionPresidioTimeoutTotal.Load(),
		"authclaw_gateway_redaction_presidio_slow_total":     redactionPresidioSlowTotal.Load(),
		"authclaw_gateway_redaction_entities_total":          redactionEntitiesTotal.Load(),
		"authclaw_gateway_redaction_tokens_created_total":    redactionTokensCreatedTotal.Load(),
		"authclaw_gateway_redaction_tokens_reused_total":     redactionTokensReusedTotal.Load(),
		"authclaw_gateway_redaction_tokens_purged_total":     redactionTokensPurgedTotal.Load(),
	}
}

func redactionHashSalt() string {
	if salt := os.Getenv("REDACTION_HASH_SALT"); strings.TrimSpace(salt) != "" {
		return salt
	}
	return "authclaw_redaction_salt_v1"
}

func loadCustomNERRecognizers() []CustomNERRecognizerConfig {
	payload := strings.TrimSpace(os.Getenv("REDACTION_CUSTOM_RECOGNIZERS_JSON"))
	if path := strings.TrimSpace(os.Getenv("REDACTION_CUSTOM_RECOGNIZERS_FILE")); path != "" {
		if data, err := os.ReadFile(path); err == nil {
			payload = strings.TrimSpace(string(data))
		} else {
			log.Printf("[REDACTION] custom_recognizers status=load_failed path=%s err=%v", path, err)
		}
	}
	if payload == "" {
		return nil
	}

	var recognizers []CustomNERRecognizerConfig
	if err := json.Unmarshal([]byte(payload), &recognizers); err != nil {
		var single CustomNERRecognizerConfig
		if singleErr := json.Unmarshal([]byte(payload), &single); singleErr != nil {
			log.Printf("[REDACTION] custom_recognizers status=parse_failed err=%v", err)
			return nil
		}
		recognizers = []CustomNERRecognizerConfig{single}
	}

	cleaned := make([]CustomNERRecognizerConfig, 0, len(recognizers))
	for _, recognizer := range recognizers {
		recognizer.Name = strings.TrimSpace(recognizer.Name)
		recognizer.EntityType = strings.ToUpper(strings.TrimSpace(recognizer.EntityType))
		if recognizer.Name == "" {
			recognizer.Name = recognizer.EntityType + "Recognizer"
		}
		if recognizer.EntityType == "" || len(recognizer.Patterns) == 0 {
			continue
		}
		if recognizer.Score <= 0 || recognizer.Score > 1 {
			recognizer.Score = 0.85
		}
		cleaned = append(cleaned, recognizer)
	}
	return cleaned
}

func customNERPresidioRecognizers() []PresidioRecognizer {
	custom := loadCustomNERRecognizers()
	recognizers := make([]PresidioRecognizer, 0, len(custom))
	for _, item := range custom {
		patterns := make([]PresidioPattern, 0, len(item.Patterns))
		for i, pattern := range item.Patterns {
			pattern = strings.TrimSpace(pattern)
			if pattern == "" {
				continue
			}
			patterns = append(patterns, PresidioPattern{
				Name:  fmt.Sprintf("%s_%d", item.Name, i+1),
				Regex: pattern,
				Score: item.Score,
			})
		}
		if len(patterns) == 0 {
			continue
		}
		recognizers = append(recognizers, PresidioRecognizer{
			Name:              item.Name,
			SupportedLanguage: "en",
			Patterns:          patterns,
			SupportedEntity:   item.EntityType,
		})
	}
	return recognizers
}

func appendCustomNERAnalyzeResults(results []AnalyzeResult, text string) []AnalyzeResult {
	for _, recognizer := range loadCustomNERRecognizers() {
		if len(recognizer.ContextKeywords) > 0 {
			lowerText := strings.ToLower(text)
			matchedContext := false
			for _, keyword := range recognizer.ContextKeywords {
				if strings.Contains(lowerText, strings.ToLower(strings.TrimSpace(keyword))) {
					matchedContext = true
					break
				}
			}
			if !matchedContext {
				continue
			}
		}
		for _, patternText := range recognizer.Patterns {
			pattern, err := regexp.Compile(patternText)
			if err != nil {
				log.Printf("[REDACTION] custom_recognizer=%s status=invalid_regex err=%v", recognizer.Name, err)
				continue
			}
			results = appendRegexAnalyzeResults(results, text, recognizer.EntityType, pattern)
		}
	}
	return results
}

func (c *PresidioClient) Analyze(ctx context.Context, text string, customRules []RegexRule) ([]AnalyzeResult, error) {
	recognizers := []PresidioRecognizer{
		{
			Name:              "HealthDataRecognizer",
			SupportedLanguage: "en",
			Patterns: []PresidioPattern{
				{
					Name:  "health_keywords",
					Regex: `(?i)\b(patient|diagnosed|treatment|prescription|symptoms|medical|disease|hospital|doctor|clinic)\b`,
					Score: 0.8,
				},
			},
			SupportedEntity: "HEALTH_DATA",
		},
		{
			Name:              "SsnRecognizer",
			SupportedLanguage: "en",
			Patterns: []PresidioPattern{
				{
					Name:  "ssn_pattern",
					Regex: `\b\d{3}-\d{2}-\d{4}\b`,
					Score: 1.0,
				},
			},
			SupportedEntity: "US_SSN",
		},
		// UK & international phone number recognizer
		// Covers: +44 7700 900123, +1-800-555-0199, 07700900123, (020) 7946 0123
		{
			Name:              "PhoneNumberRecognizer",
			SupportedLanguage: "en",
			Patterns: []PresidioPattern{
				{
					Name:  "intl_phone",
					Regex: `(\+?[\d\s\-\(\)]{7,20})`,
					Score: 0.6,
				},
				{
					Name:  "uk_phone",
					Regex: `(\+44\s?[\d\s]{10,14}|0\d{4}\s?\d{6}|0\d{3}\s?\d{3}\s?\d{4})`,
					Score: 0.85,
				},
			},
			SupportedEntity: "PHONE_NUMBER",
		},
		// UK National Insurance Number: AB123456C pattern
		{
			Name:              "UKNationalIDRecognizer",
			SupportedLanguage: "en",
			Patterns: []PresidioPattern{
				{
					Name:  "uk_nino",
					Regex: `\b[A-CEGHJ-PR-TW-Z]{2}[0-9]{6}[A-D]\b`,
					Score: 0.95,
				},
				// Employee ID patterns (EMP-YYYY-NNN)
				{
					Name:  "employee_id",
					Regex: `\bEMP-\d{4}-\d{3,}\b`,
					Score: 0.9,
				},
				// UK Passport-style national IDs
				{
					Name:  "uk_passport",
					Regex: `\b[0-9]{9}\b`,
					Score: 0.5,
				},
			},
			SupportedEntity: "UK_NATIONAL_ID",
		},
		// Generic staff/manager name context recognizer
		{
			Name:              "ContextualNameRecognizer",
			SupportedLanguage: "en",
			Patterns: []PresidioPattern{
				{
					Name:  "manager_field",
					Regex: `(?i)(?:Manager|Supervisor|Reported to|Managed by|Director|Lead):\s*([A-Z][a-z]+ [A-Z][a-z]+)`,
					Score: 0.9,
				},
			},
			SupportedEntity: "PERSON",
		},
	}

	for _, rule := range customRules {
		recognizers = append(recognizers, PresidioRecognizer{
			Name:              rule.Name + "Recognizer",
			SupportedLanguage: "en",
			Patterns: []PresidioPattern{
				{
					Name:  rule.Name,
					Regex: rule.Pattern,
					Score: 1.0,
				},
			},
			SupportedEntity: strings.ToUpper(strings.ReplaceAll(rule.Name, " ", "_")),
		})
	}
	recognizers = append(recognizers, customNERPresidioRecognizers()...)

	reqBody := AnalyzeRequest{
		Text:             text,
		Language:         "en",
		AdHocRecognizers: recognizers,
		Entities: []string{
			"PERSON",
			"EMAIL_ADDRESS",
			"PHONE_NUMBER",
			"US_SSN",
			"HEALTH_DATA",
			"UK_NATIONAL_ID",
			"NRP",    // Presidio built-in: nationality, religious/political group
			"UK_NHS", // Presidio built-in: NHS numbers
			"DATE_TIME",
		},
	}

	for _, rule := range customRules {
		reqBody.Entities = append(reqBody.Entities, strings.ToUpper(strings.ReplaceAll(rule.Name, " ", "_")))
	}
	for _, recognizer := range loadCustomNERRecognizers() {
		reqBody.Entities = append(reqBody.Entities, recognizer.EntityType)
	}

	jsonBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", c.BaseURL+"/analyze", bytes.NewBuffer(jsonBytes))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := presidioClientHTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("presidio returned status %d: %s", resp.StatusCode, string(body))
	}

	var results []AnalyzeResult
	if err := json.NewDecoder(resp.Body).Decode(&results); err != nil {
		return nil, err
	}

	return results, nil
}

func analyzePromptWithFallback(ctx context.Context, presidio *PresidioClient, prompt string, customRules []RegexRule) []AnalyzeResult {
	start := time.Now()
	redactionAnalyzeRequestsTotal.Add(1)
	if envBool("REDACTION_LOCAL_ANALYZER_ONLY", false) {
		return fallbackAnalyze(prompt, customRules)
	}
	if presidioIsOffline(presidio.BaseURL) {
		results := fallbackAnalyze(prompt, customRules)
		redactionPresidioFallbackTotal.Add(1)
		return results
	}
	release, acquired := acquirePresidioSlot(ctx)
	if !acquired {
		fallbackStart := time.Now()
		results := fallbackAnalyze(prompt, customRules)
		redactionPresidioFallbackTotal.Add(1)
		redactionPresidioTimeoutTotal.Add(1)
		log.Printf(
			"[REDACTION] analyzer=presidio status=fallback reason=concurrency_limit fallback_duration_ms=%d prompt_chars=%d findings=%d",
			time.Since(fallbackStart).Milliseconds(),
			len([]rune(prompt)),
			len(results),
		)
		return results
	}
	defer release()

	analyzeCtx, cancel := context.WithTimeout(ctx, presidioAnalyzeTimeout())
	defer cancel()

	results, err := presidio.Analyze(analyzeCtx, prompt, customRules)
	duration := time.Since(start)
	if err != nil {
		markPresidioFailure(presidio.BaseURL)
		fallbackStart := time.Now()
		results = fallbackAnalyze(prompt, customRules)
		redactionPresidioFallbackTotal.Add(1)
		if analyzeCtx.Err() != nil || strings.Contains(strings.ToLower(err.Error()), "timeout") || strings.Contains(strings.ToLower(err.Error()), "deadline") {
			redactionPresidioTimeoutTotal.Add(1)
		}
		log.Printf(
			"[REDACTION] analyzer=presidio status=fallback duration_ms=%d fallback_duration_ms=%d prompt_chars=%d err=%v",
			duration.Milliseconds(),
			time.Since(fallbackStart).Milliseconds(),
			len([]rune(prompt)),
			err,
		)
		return results
	}

	results = appendCustomRuleAnalyzeResults(results, prompt, customRules)
	results = appendCustomNERAnalyzeResults(results, prompt)
	markPresidioSuccess(presidio.BaseURL)
	redactionPresidioSuccessTotal.Add(1)
	if duration > presidioSlowLogThreshold() {
		redactionPresidioSlowTotal.Add(1)
		log.Printf(
			"[REDACTION] analyzer=presidio status=slow duration_ms=%d prompt_chars=%d findings=%d",
			duration.Milliseconds(),
			len([]rune(prompt)),
			len(results),
		)
	}
	return results
}

func byteIndexToRuneIndex(text string, byteIndex int) int {
	if byteIndex <= 0 {
		return 0
	}
	if byteIndex >= len(text) {
		return len([]rune(text))
	}
	return len([]rune(text[:byteIndex]))
}

func appendRegexAnalyzeResults(results []AnalyzeResult, text, entityType string, pattern *regexp.Regexp) []AnalyzeResult {
	for _, loc := range pattern.FindAllStringSubmatchIndex(text, -1) {
		startIndex := 0
		endIndex := 1
		if len(loc) >= 4 && loc[2] >= 0 && loc[3] >= 0 {
			startIndex = 2
			endIndex = 3
		}
		if loc[startIndex] < 0 || loc[endIndex] < 0 {
			continue
		}
		results = append(results, AnalyzeResult{
			Start:      byteIndexToRuneIndex(text, loc[startIndex]),
			End:        byteIndexToRuneIndex(text, loc[endIndex]),
			EntityType: entityType,
			Score:      1.0,
		})
	}
	return results
}

func normalizedCustomEntity(rule RegexRule) string {
	entity := strings.TrimSpace(rule.Entity)
	if entity == "" {
		entity = rule.Name
	}
	entity = strings.ToUpper(strings.ReplaceAll(entity, " ", "_"))
	if strings.Contains(entity, "PHONE") || strings.Contains(entity, "MOBILE") {
		return "PHONE_NUMBER"
	}
	return entity
}

func appendCustomRuleAnalyzeResults(results []AnalyzeResult, text string, customRules []RegexRule) []AnalyzeResult {
	for _, rule := range customRules {
		if rule.Pattern == "" || rule.normalizedAction() == "block" {
			continue
		}
		pattern, err := regexp.Compile(rule.Pattern)
		if err != nil {
			log.Printf("Skipping invalid custom regex rule %q: %v", rule.Name, err)
			continue
		}
		results = appendRegexAnalyzeResults(results, text, normalizedCustomEntity(rule), pattern)
	}
	return results
}

var (
	phoneLikePattern = regexp.MustCompile(`^\+?\d[\d\s().-]{7,}\d$`)
	fallbackBuiltIns = []struct {
		entityType string
		pattern    *regexp.Regexp
	}{
		{"EMAIL_ADDRESS", regexp.MustCompile(`(?i)\b[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}\b`)},
		{"US_SSN", regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`)},
		{"PHONE_NUMBER", regexp.MustCompile(`(?i)(?:\+?\d[\d\s().-]{7,}\d)`)},
		{"HEALTH_DATA", regexp.MustCompile(`(?i)\b(patient|diagnosed|treatment|prescription|symptoms|medical|disease|hospital|doctor|clinic)\b`)},
		{"PERSON", regexp.MustCompile(`(?i)\b(?:my name is|name is|patient|manager|supervisor|reported to|managed by|call|contact|email|text)\s*:?\s*([A-Z][a-z]+ [A-Z][a-z]+)\b`)},
	}
	redactionRuntimeConfigCache sync.Map
)

func normalizeDetectedEntity(entityType, originalValue string, customRules []RegexRule) string {
	entity := strings.ToUpper(strings.TrimSpace(entityType))
	trimmed := strings.TrimSpace(originalValue)
	for _, rule := range customRules {
		if rule.Pattern == "" || !strings.Contains(normalizedCustomEntity(rule), "PHONE") {
			continue
		}
		pattern, err := regexp.Compile(rule.Pattern)
		if err == nil && pattern.MatchString(trimmed) {
			return "PHONE_NUMBER"
		}
	}
	if entity == "UK_NHS" && phoneLikePattern.MatchString(trimmed) {
		return "PHONE_NUMBER"
	}
	return entity
}

func fallbackAnalyze(text string, customRules []RegexRule) []AnalyzeResult {
	results := []AnalyzeResult{}
	for _, item := range fallbackBuiltIns {
		results = appendRegexAnalyzeResults(results, text, item.entityType, item.pattern)
	}
	results = appendCustomRuleAnalyzeResults(results, text, customRules)
	return appendCustomNERAnalyzeResults(results, text)
}

// Encryption Helpers (AES-256 CBC Deterministic)
var encryptionKey []byte

const secretEnvelopePrefix = "authclaw-secret-v1:"
const secretEnvelopeV2Prefix = "authclaw-secret-v2:"

func isProductionEnv() bool {
	env := strings.ToLower(strings.TrimSpace(os.Getenv("AUTHCLAW_ENV")))
	return env == "production" || env == "prod"
}

func configuredEnvelopeKey() string {
	keyStr := os.Getenv("ENCRYPTION_KEY")
	if keyStr == "" {
		keyStr = os.Getenv("ENVELOPE_KEY")
	}
	return keyStr
}

func secretProvider() string {
	provider := strings.ToLower(strings.TrimSpace(os.Getenv("AUTHCLAW_SECRET_PROVIDER")))
	if provider == "" {
		return "env"
	}
	return provider
}

func secretKeyVersion() string {
	version := strings.TrimSpace(os.Getenv("AUTHCLAW_SECRET_KEY_VERSION"))
	if version == "" {
		return "v1"
	}
	return version
}

func envVersionedEnvelopeKey(version string) string {
	suffix := strings.ToUpper(strings.ReplaceAll(version, "-", "_"))
	if key := os.Getenv("ENVELOPE_KEY_" + suffix); key != "" {
		return key
	}
	return configuredEnvelopeKey()
}

func ValidateEnvelopeKeyConfig() error {
	if !isProductionEnv() {
		return nil
	}
	provider := secretProvider()
	version := secretKeyVersion()
	if os.Getenv("AUTHCLAW_SECRET_KEY_VERSION") == "" {
		return fmt.Errorf("AUTHCLAW_SECRET_KEY_VERSION must be set in production")
	}
	if provider != "env" {
		return fmt.Errorf("gateway supports AUTHCLAW_SECRET_PROVIDER=env; configure backend/gateway with decrypted runtime envelope material for provider %q", provider)
	}
	keyStr := envVersionedEnvelopeKey(version)
	if keyStr == "" || keyStr == "authclaw-default-32-byte-key-12" || strings.HasPrefix(keyStr, "demo-") || strings.Contains(keyStr, "change-me") {
		return fmt.Errorf("ENVELOPE_KEY or ENCRYPTION_KEY must be set to a non-demo value in production")
	}
	if len([]byte(keyStr)) < 32 {
		return fmt.Errorf("ENVELOPE_KEY or ENCRYPTION_KEY must be at least 32 bytes in production")
	}
	return nil
}

func serviceTLSEnforced() bool {
	value := strings.ToLower(strings.TrimSpace(os.Getenv("AUTHCLAW_REQUIRE_SERVICE_TLS")))
	if value == "" {
		return isProductionEnv()
	}
	return value == "1" || value == "true" || value == "yes" || value == "on"
}

func ValidateServiceTLSConfig() error {
	if !serviceTLSEnforced() {
		return nil
	}
	for _, name := range []string{"OPA_URL", "PRESIDIO_URL"} {
		if !strings.HasPrefix(strings.TrimSpace(os.Getenv(name)), "https://") {
			return fmt.Errorf("%s must use https when service TLS is required", name)
		}
	}
	return nil
}

func normalizeEnvelopeKey(keyStr string) []byte {
	if keyStr == "" {
		keyStr = "authclaw-default-32-byte-key-12"
	}
	if len(keyStr) > 32 {
		return []byte(keyStr[:32])
	}
	if len(keyStr) < 32 {
		k := make([]byte, 32)
		copy(k, keyStr)
		return k
	}
	return []byte(keyStr)
}

func initEncryptionKey() {
	encryptionKey = normalizeEnvelopeKey(configuredEnvelopeKey())
}

func secretEnvelopeKey(provider, version string) ([]byte, error) {
	if provider != "env" {
		return nil, fmt.Errorf("unsupported secret provider %q in gateway", provider)
	}
	return normalizeEnvelopeKey(envVersionedEnvelopeKey(version)), nil
}

func pkcs7Pad(data []byte, blockSize int) []byte {
	padding := blockSize - (len(data) % blockSize)
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padText...)
}

func pkcs7Unpad(data []byte) ([]byte, error) {
	length := len(data)
	if length == 0 {
		return nil, fmt.Errorf("empty data")
	}
	padding := int(data[length-1])
	if padding < 1 || padding > 16 {
		return nil, fmt.Errorf("invalid padding")
	}
	for i := length - padding; i < length; i++ {
		if int(data[i]) != padding {
			return nil, fmt.Errorf("invalid padding content")
		}
	}
	return data[:length-padding], nil
}

func EncryptDeterministic(plaintext string) (string, error) {
	if encryptionKey == nil {
		initEncryptionKey()
	}
	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return "", err
	}
	padded := pkcs7Pad([]byte(plaintext), aes.BlockSize)

	h := sha256.New()
	h.Write([]byte(plaintext))
	h.Write(encryptionKey)
	iv := h.Sum(nil)[:aes.BlockSize]

	ciphertext := make([]byte, len(padded))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, padded)

	combined := append(iv, ciphertext...)
	return base64.StdEncoding.EncodeToString(combined), nil
}

func DecryptDeterministic(ciphertextStr string) (string, error) {
	if encryptionKey == nil {
		initEncryptionKey()
	}
	data, err := base64.StdEncoding.DecodeString(ciphertextStr)
	if err != nil {
		return "", err
	}
	if len(data) < aes.BlockSize {
		return "", fmt.Errorf("ciphertext too short")
	}
	iv := data[:aes.BlockSize]
	ciphertext := data[aes.BlockSize:]

	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return "", err
	}

	if len(ciphertext)%aes.BlockSize != 0 {
		return "", fmt.Errorf("ciphertext block size invalid")
	}

	decrypted := make([]byte, len(ciphertext))
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(decrypted, ciphertext)

	unpadded, err := pkcs7Unpad(decrypted)
	if err != nil {
		return "", err
	}

	return string(unpadded), nil
}

func EncryptSecret(plaintext string) (string, error) {
	provider := secretProvider()
	version := secretKeyVersion()
	key, err := secretEnvelopeKey(provider, version)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	ciphertext := gcm.Seal(nil, nonce, []byte(plaintext), nil)
	combined := append(nonce, ciphertext...)
	return secretEnvelopeV2Prefix + provider + ":" + version + ":" + base64.StdEncoding.EncodeToString(combined), nil
}

func DecryptSecret(ciphertextStr string) (string, error) {
	if strings.HasPrefix(ciphertextStr, secretEnvelopeV2Prefix) {
		envelope := strings.TrimPrefix(ciphertextStr, secretEnvelopeV2Prefix)
		parts := strings.SplitN(envelope, ":", 3)
		if len(parts) != 3 {
			return "", fmt.Errorf("invalid v2 secret envelope")
		}
		provider, version, payload := parts[0], parts[1], parts[2]
		key, err := secretEnvelopeKey(provider, version)
		if err != nil {
			return "", err
		}
		data, err := base64.StdEncoding.DecodeString(payload)
		if err != nil {
			return "", err
		}
		block, err := aes.NewCipher(key)
		if err != nil {
			return "", err
		}
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			return "", err
		}
		if len(data) <= gcm.NonceSize() {
			return "", fmt.Errorf("ciphertext too short")
		}
		nonce := data[:gcm.NonceSize()]
		ciphertext := data[gcm.NonceSize():]
		plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
		if err != nil {
			return "", err
		}
		return string(plaintext), nil
	}
	if !strings.HasPrefix(ciphertextStr, secretEnvelopePrefix) {
		return DecryptDeterministic(ciphertextStr)
	}
	if encryptionKey == nil {
		initEncryptionKey()
	}
	payload := strings.TrimPrefix(ciphertextStr, secretEnvelopePrefix)
	data, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	if len(data) <= gcm.NonceSize() {
		return "", fmt.Errorf("ciphertext too short")
	}
	nonce := data[:gcm.NonceSize()]
	ciphertext := data[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

// DB Tenant Context Execution Helper
func RunInTenantTx(ctx context.Context, tenantID string, fn func(*sql.Tx) error) error {
	tx, err := DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	_, err = tx.ExecContext(ctx, "SELECT set_config('app.current_tenant_id', $1, true)", tenantID)
	if err != nil {
		return err
	}

	if err := fn(tx); err != nil {
		return err
	}

	return tx.Commit()
}

// Tokenization Mappings Store & Helpers
func hashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

func cryptoRandInt(max int) int {
	var n uint32
	binary.Read(rand.Reader, binary.BigEndian, &n)
	return int(n % uint32(max))
}

func generateShortUUID() string {
	b := make([]byte, 4)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func getSyntheticBase(entityType string) string {
	switch entityType {
	case "PERSON":
		names := []string{"Alice Smith", "Bob Jones", "Charlie Brown", "Diana Prince", "Evan Wright", "Fiona Gallagher", "George Clark", "Hannah Abbott"}
		return names[cryptoRandInt(len(names))]
	case "EMAIL_ADDRESS":
		domains := []string{"example.org", "testmail.net", "dummycorp.com"}
		return fmt.Sprintf("user.%d@%s", cryptoRandInt(1000), domains[cryptoRandInt(len(domains))])
	case "PHONE_NUMBER":
		return fmt.Sprintf("555-01%02d", cryptoRandInt(100))
	case "US_SSN":
		return fmt.Sprintf("%03d-%02d-%04d", cryptoRandInt(1000), cryptoRandInt(100), cryptoRandInt(10000))
	case "HEALTH_DATA":
		conditions := []string{"mild condition", "routine treatment", "general symptoms", "medical issue"}
		return conditions[cryptoRandInt(len(conditions))]
	default:
		return "synthetic-placeholder"
	}
}

func isTokenValueExists(ctx context.Context, tx *sql.Tx, tenantID, tokenValue string) (bool, error) {
	var exists bool
	err := tx.QueryRowContext(ctx,
		"SELECT EXISTS(SELECT 1 FROM redaction_tokens WHERE tenant_id = $1 AND token_value = $2)",
		tenantID, tokenValue,
	).Scan(&exists)
	return exists, err
}

func GenerateTokenValue(ctx context.Context, tx *sql.Tx, tenantID, originalValue, entityType, strategy string) (string, error) {
	switch strategy {
	case "mask":
		uuidPart := generateShortUUID()
		return fmt.Sprintf("[REDACTED_%s_%s]", entityType, uuidPart), nil

	case "hash":
		h := sha256.New()
		h.Write([]byte(tenantID))
		h.Write([]byte(":"))
		h.Write([]byte(originalValue))
		h.Write([]byte(":"))
		h.Write([]byte(redactionHashSalt()))
		hashPart := hex.EncodeToString(h.Sum(nil))[:12]
		return fmt.Sprintf("[HASH_%s_%s]", entityType, hashPart), nil

	case "synthetic":
		baseVal := getSyntheticBase(entityType)
		tokenVal := baseVal
		exists, err := isTokenValueExists(ctx, tx, tenantID, tokenVal)
		if err != nil {
			return "", err
		}
		counter := 1
		for exists {
			tokenVal = fmt.Sprintf("%s (%d)", baseVal, counter)
			exists, err = isTokenValueExists(ctx, tx, tenantID, tokenVal)
			if err != nil {
				return "", err
			}
			counter++
		}
		return tokenVal, nil

	default:
		return "[REDACTED]", nil
	}
}

func purgeExpiredRedactionTokens(ctx context.Context, tx *sql.Tx, tenantID string) (int64, error) {
	result, err := tx.ExecContext(ctx,
		"DELETE FROM redaction_tokens WHERE tenant_id = $1 AND expires_at IS NOT NULL AND expires_at <= NOW()",
		tenantID,
	)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

func retentionDaysOrDefault(days int) int {
	if days <= 0 {
		return 90
	}
	if days > 3650 {
		return 3650
	}
	return days
}

func GetOrCreateRedactionToken(ctx context.Context, tenantID, originalValue, entityType, strategy string) (string, error) {
	return GetOrCreateRedactionTokenWithRetention(ctx, tenantID, originalValue, entityType, strategy, 90)
}

func GetOrCreateRedactionTokenWithRetention(ctx context.Context, tenantID, originalValue, entityType, strategy string, retentionDays int) (string, error) {
	return getOrCreateRedactionTokenWithRetention(ctx, tenantID, originalValue, entityType, strategy, retentionDays, false)
}

type cachedRedactionToken struct {
	token     string
	expiresAt time.Time
}

func redactionTokenCacheKey(tenantID, encVal, entityType, strategy string, retentionDays int) string {
	h := sha256.New()
	h.Write([]byte(tenantID))
	h.Write([]byte{0})
	h.Write([]byte(encVal))
	h.Write([]byte{0})
	h.Write([]byte(entityType))
	h.Write([]byte{0})
	h.Write([]byte(strategy))
	h.Write([]byte{0})
	h.Write([]byte(strconv.Itoa(retentionDaysOrDefault(retentionDays))))
	return hex.EncodeToString(h.Sum(nil))
}

func touchCachedRedactionToken(tenantID, encVal, entityType, strategy string) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = RunInTenantTx(ctx, tenantID, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx,
			`UPDATE redaction_tokens
			 SET entity_type = COALESCE(entity_type, $3),
			     last_used_at = NOW(),
			     use_count = use_count + 1
			 WHERE tenant_id = $1
			   AND original_value = $2
			   AND strategy = $4
			   AND (expires_at IS NULL OR expires_at > NOW())`,
			tenantID, encVal, entityType, strategy,
		)
		return err
	})
}

func getOrCreateRedactionTokenWithRetention(ctx context.Context, tenantID, originalValue, entityType, strategy string, retentionDays int, useCache bool) (string, error) {
	encVal, err := EncryptDeterministic(originalValue)
	if err != nil {
		return "", err
	}
	cacheTTL := redactionTokenCacheTTL()
	cacheKey := ""
	if useCache && cacheTTL > 0 {
		cacheKey = redactionTokenCacheKey(tenantID, encVal, entityType, strategy, retentionDays)
		if raw, ok := redactionTokenCache.Load(cacheKey); ok {
			cached, ok := raw.(cachedRedactionToken)
			if ok && time.Now().Before(cached.expiresAt) {
				redactionTokensReusedTotal.Add(1)
				go touchCachedRedactionToken(tenantID, encVal, entityType, strategy)
				return cached.token, nil
			}
			redactionTokenCache.Delete(cacheKey)
		}
	}

	shouldRelabelToken := func(tokenValue string) bool {
		if entityType != "PHONE_NUMBER" {
			return false
		}
		return strings.Contains(tokenValue, "_UK_NHS_") ||
			strings.Contains(tokenValue, "_UK_NATIONAL_ID_")
	}

	var tokenVal string

	err = RunInTenantTx(ctx, tenantID, func(tx *sql.Tx) error {
		purged, purgeErr := purgeExpiredRedactionTokens(ctx, tx, tenantID)
		if purgeErr != nil {
			return purgeErr
		}
		if purged > 0 {
			redactionTokensPurgedTotal.Add(uint64(purged))
		}

		var tokenID string
		err := tx.QueryRowContext(ctx,
			`SELECT id::text, token_value
			 FROM redaction_tokens
			 WHERE tenant_id = $1
			   AND original_value = $2
			   AND strategy = $3
			   AND (expires_at IS NULL OR expires_at > NOW())
			 LIMIT 1`,
			tenantID, encVal, strategy,
		).Scan(&tokenID, &tokenVal)

		if err == nil {
			redactionTokensReusedTotal.Add(1)
			if shouldRelabelToken(tokenVal) {
				tokenVal, err = GenerateTokenValue(ctx, tx, tenantID, originalValue, entityType, strategy)
				if err != nil {
					return err
				}
				_, err = tx.ExecContext(ctx,
					`UPDATE redaction_tokens
					 SET token_value = $1,
					     token_hash = $2,
					     entity_type = $5,
					     last_used_at = NOW(),
					     use_count = use_count + 1
					 WHERE tenant_id = $3 AND id = $4::uuid`,
					tokenVal, hashToken(tokenVal), tenantID, tokenID, entityType,
				)
				return err
			}
			_, err = tx.ExecContext(ctx,
				`UPDATE redaction_tokens
				 SET entity_type = COALESCE(entity_type, $3),
				     last_used_at = NOW(),
				     use_count = use_count + 1
				 WHERE tenant_id = $1 AND id = $2::uuid`,
				tenantID, tokenID, entityType,
			)
			return err
		}
		if err != sql.ErrNoRows {
			return err
		}

		tokenVal, err = GenerateTokenValue(ctx, tx, tenantID, originalValue, entityType, strategy)
		if err != nil {
			return err
		}

		tokenHash := hashToken(tokenVal)

		err = tx.QueryRowContext(ctx, `
			INSERT INTO redaction_tokens (
				id, tenant_id, original_value, token_hash, token_value, strategy, entity_type, expires_at, last_used_at, use_count, created_at
			)
			VALUES (gen_random_uuid(), $1, $2, $3, $4, $5, $6, NOW() + ($7::text || ' days')::interval, NOW(), 1, NOW())
			ON CONFLICT (tenant_id, original_value, strategy)
			DO UPDATE SET
				token_value = redaction_tokens.token_value,
				entity_type = COALESCE(redaction_tokens.entity_type, EXCLUDED.entity_type),
				last_used_at = NOW(),
				use_count = redaction_tokens.use_count + 1
			RETURNING token_value
		`,
			tenantID, encVal, tokenHash, tokenVal, strategy, entityType, retentionDaysOrDefault(retentionDays),
		).Scan(&tokenVal)
		if err == nil {
			redactionTokensCreatedTotal.Add(1)
		}
		return err
	})

	if err != nil {
		return "", err
	}
	if useCache && cacheTTL > 0 && cacheKey != "" {
		redactionTokenCache.Store(cacheKey, cachedRedactionToken{
			token:     tokenVal,
			expiresAt: time.Now().Add(cacheTTL),
		})
	}
	return tokenVal, nil
}

func GetRedactionRuntimeConfig(ctx context.Context, tenantID string) RedactionRuntimeConfig {
	config := RedactionRuntimeConfig{Strategy: "mask", TokenRetentionDays: 90}
	if tenantID == "" {
		return config
	}
	ttl := time.Duration(envInt("REDACTION_RUNTIME_CONFIG_CACHE_TTL_MS", 0)) * time.Millisecond
	if ttl > 0 {
		if raw, ok := redactionRuntimeConfigCache.Load(tenantID); ok {
			cached, ok := raw.(struct {
				config    RedactionRuntimeConfig
				expiresAt time.Time
			})
			if ok && time.Now().Before(cached.expiresAt) {
				return cached.config
			}
			redactionRuntimeConfigCache.Delete(tenantID)
		}
	}
	err := RunInTenantTx(ctx, tenantID, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx,
			`SELECT redaction_strategy, COALESCE(redaction_token_retention_days, 90)
			 FROM gateway_configs
			 WHERE tenant_id = $1 AND is_active = true
			 ORDER BY updated_at DESC
			 LIMIT 1`,
			tenantID,
		).Scan(&config.Strategy, &config.TokenRetentionDays)
	})
	if err != nil || config.Strategy == "" {
		config.Strategy = "mask"
	}
	config.TokenRetentionDays = retentionDaysOrDefault(config.TokenRetentionDays)
	if ttl > 0 {
		redactionRuntimeConfigCache.Store(tenantID, struct {
			config    RedactionRuntimeConfig
			expiresAt time.Time
		}{config: config, expiresAt: time.Now().Add(ttl)})
	}
	return config
}

func redactTextWithResults(ctx context.Context, tenantID, text string, customRules []RegexRule, runtimeConfig RedactionRuntimeConfig, results []AnalyzeResult) (string, map[string]string, error) {
	tokenMap := make(map[string]string)

	sort.Slice(results, func(i, j int) bool {
		if results[i].Start == results[j].Start {
			return results[i].End > results[j].End
		}
		return results[i].Start > results[j].Start
	})

	runes := []rune(text)
	lastProcessedStart := len(runes) + 1

	for _, entity := range results {
		if entity.Start < 0 || entity.End > len(runes) || entity.Start >= entity.End {
			continue
		}
		if entity.End > lastProcessedStart {
			continue
		}

		originalVal := string(runes[entity.Start:entity.End])
		entityType := normalizeDetectedEntity(entity.EntityType, originalVal, customRules)
		tokenVal, err := getOrCreateRedactionTokenWithRetention(
			ctx,
			tenantID,
			originalVal,
			entityType,
			runtimeConfig.Strategy,
			runtimeConfig.TokenRetentionDays,
			true,
		)
		if err != nil {
			return "", nil, err
		}
		redactionEntitiesTotal.Add(1)
		tokenMap[tokenVal] = originalVal
		runes = append(runes[:entity.Start], append([]rune(tokenVal), runes[entity.End:]...)...)
		lastProcessedStart = entity.Start
	}

	return string(runes), tokenMap, nil
}

// RedactPrompts runs Presidio Analyzer and tokenizes original prompts
func RedactPrompts(ctx context.Context, tenantID string, prompts []string, customRules []RegexRule) ([]string, map[string]string, error) {
	presidio := NewPresidioClient()
	runtimeConfig := GetRedactionRuntimeConfig(ctx, tenantID)
	tokenMap := make(map[string]string)
	redactedPrompts := make([]string, len(prompts))

	for i, prompt := range prompts {
		results := analyzePromptWithFallback(ctx, presidio, prompt, customRules)
		redacted, promptTokenMap, err := redactTextWithResults(ctx, tenantID, prompt, customRules, runtimeConfig, results)
		if err != nil {
			return nil, nil, err
		}
		for token, original := range promptTokenMap {
			tokenMap[token] = original
		}
		redactedPrompts[i] = redacted
	}

	return redactedPrompts, tokenMap, nil
}

// Static Reversal
func ReverseStaticResponse(body []byte, tokenMap map[string]string) []byte {
	bodyStr := string(body)
	for token, original := range tokenMap {
		bodyStr = strings.ReplaceAll(bodyStr, token, original)
	}
	return []byte(bodyStr)
}

func redactOutboundText(ctx context.Context, tenantID, text string, customRules []RegexRule, runtimeConfig RedactionRuntimeConfig) (string, map[string]string, error) {
	results := fallbackAnalyze(text, customRules)
	return redactTextWithResults(ctx, tenantID, text, customRules, runtimeConfig, results)
}

func ProtectProviderResponseBody(ctx context.Context, tenantID, provider string, body []byte, inboundTokenMap map[string]string, customRules []RegexRule, runtimeConfig RedactionRuntimeConfig) ([]byte, map[string]string, error) {
	reversed := ReverseStaticResponse(body, inboundTokenMap)
	outboundTokenMap := make(map[string]string)
	if tenantID == "" {
		return reversed, outboundTokenMap, nil
	}
	var transformErr error

	modifiedJSON, ok, err := rewriteDeltaText(reversed, provider, func(text string) string {
		redacted, textTokenMap, redactErr := redactOutboundText(ctx, tenantID, text, customRules, runtimeConfig)
		if redactErr != nil {
			transformErr = redactErr
			return text
		}
		for token, original := range textTokenMap {
			outboundTokenMap[token] = original
		}
		return redacted
	})
	if err != nil {
		return nil, nil, err
	}
	if transformErr != nil {
		return nil, nil, transformErr
	}
	if ok {
		return modifiedJSON, outboundTokenMap, nil
	}

	return reversed, outboundTokenMap, nil
}

// Streaming Reversal
type StreamReverser struct {
	tokenMap map[string]string
	buffer   string
}

func NewStreamReverser(tokenMap map[string]string) *StreamReverser {
	return &StreamReverser{tokenMap: tokenMap}
}

func (sr *StreamReverser) ProcessChunk(chunk string) string {
	sr.buffer += chunk

	for token, original := range sr.tokenMap {
		sr.buffer = strings.ReplaceAll(sr.buffer, token, original)
	}

	longestPrefixLen := 0
	for token := range sr.tokenMap {
		for i := 1; i < len(token); i++ {
			prefix := token[:i]
			if strings.HasSuffix(sr.buffer, prefix) {
				if i > longestPrefixLen {
					longestPrefixLen = i
				}
			}
		}
	}

	safeLen := len(sr.buffer) - longestPrefixLen
	if safeLen <= 0 {
		return ""
	}

	output := sr.buffer[:safeLen]
	sr.buffer = sr.buffer[safeLen:]
	return output
}

func (sr *StreamReverser) Flush() string {
	out := sr.buffer
	sr.buffer = ""
	return out
}

type StreamOutboundRedactor struct {
	tenantID      string
	customRules   []RegexRule
	runtimeConfig RedactionRuntimeConfig
	buffer        string
	tailRunes     int
}

func NewStreamOutboundRedactor(tenantID string, customRules []RegexRule, runtimeConfig RedactionRuntimeConfig) *StreamOutboundRedactor {
	return &StreamOutboundRedactor{
		tenantID:      tenantID,
		customRules:   customRules,
		runtimeConfig: runtimeConfig,
		tailRunes:     envBoundedInt("REDACTION_STREAM_TAIL_RUNES", 128, 32, 2048),
	}
}

func splitSafeRunePrefix(text string, tailRunes int) (string, string) {
	runes := []rune(text)
	if len(runes) <= tailRunes {
		return "", text
	}
	return string(runes[:len(runes)-tailRunes]), string(runes[len(runes)-tailRunes:])
}

func (sr *StreamOutboundRedactor) ProcessChunk(ctx context.Context, chunk string) string {
	if chunk == "" {
		return ""
	}
	sr.buffer += chunk
	safe, tail := splitSafeRunePrefix(sr.buffer, sr.tailRunes)
	if safe == "" {
		sr.buffer = tail
		return ""
	}
	redacted, _, err := redactOutboundText(ctx, sr.tenantID, safe, sr.customRules, sr.runtimeConfig)
	if err != nil {
		log.Printf("[REDACTION] outbound_stream status=redact_failed err=%v", err)
		sr.buffer = tail
		return safe
	}
	sr.buffer = tail
	return redacted
}

func (sr *StreamOutboundRedactor) Flush(ctx context.Context) string {
	if sr.buffer == "" {
		return ""
	}
	buffer := sr.buffer
	sr.buffer = ""
	redacted, _, err := redactOutboundText(ctx, sr.tenantID, buffer, sr.customRules, sr.runtimeConfig)
	if err != nil {
		log.Printf("[REDACTION] outbound_stream status=flush_failed err=%v", err)
		return buffer
	}
	return redacted
}

type StaticReversalReader struct {
	originalBody io.ReadCloser
	reverser     *StreamReverser
	outBuffer    bytes.Buffer
	eof          bool
}

func NewStaticReversalReader(originalBody io.ReadCloser, tokenMap map[string]string) *StaticReversalReader {
	return &StaticReversalReader{
		originalBody: originalBody,
		reverser:     NewStreamReverser(tokenMap),
	}
}

func (s *StaticReversalReader) Read(p []byte) (int, error) {
	if s.outBuffer.Len() > 0 {
		return s.outBuffer.Read(p)
	}
	if s.eof {
		return 0, io.EOF
	}

	chunk := make([]byte, 32*1024)
	n, err := s.originalBody.Read(chunk)
	if n > 0 {
		s.outBuffer.WriteString(s.reverser.ProcessChunk(string(chunk[:n])))
		if s.outBuffer.Len() > 0 {
			return s.outBuffer.Read(p)
		}
	}
	if err == io.EOF {
		s.eof = true
		s.outBuffer.WriteString(s.reverser.Flush())
		if s.outBuffer.Len() > 0 {
			return s.outBuffer.Read(p)
		}
		return 0, io.EOF
	}
	if err != nil {
		return 0, err
	}
	return s.Read(p)
}

func (s *StaticReversalReader) Close() error {
	return s.originalBody.Close()
}

type StreamingReversalReader struct {
	originalBody  io.ReadCloser
	scanner       *bufio.Scanner
	reverser      *StreamReverser
	outbound      *StreamOutboundRedactor
	ctx           context.Context
	provider      string
	outBuffer     bytes.Buffer
	lastSSEPrefix string
	sawStructured bool
	eof           bool
}

func NewStreamingReversalReader(originalBody io.ReadCloser, tokenMap map[string]string, provider string) *StreamingReversalReader {
	return NewStreamingProtectionReader(context.Background(), originalBody, tokenMap, provider, "", nil, RedactionRuntimeConfig{})
}

func NewStreamingProtectionReader(ctx context.Context, originalBody io.ReadCloser, tokenMap map[string]string, provider, tenantID string, customRules []RegexRule, runtimeConfig RedactionRuntimeConfig) *StreamingReversalReader {
	scanner := bufio.NewScanner(originalBody)
	scanner.Buffer(make([]byte, 0, 64*1024), 10*1024*1024)
	var outbound *StreamOutboundRedactor
	if tenantID != "" {
		outbound = NewStreamOutboundRedactor(tenantID, customRules, runtimeConfig)
	}
	return &StreamingReversalReader{
		originalBody: originalBody,
		scanner:      scanner,
		reverser:     NewStreamReverser(tokenMap),
		outbound:     outbound,
		ctx:          ctx,
		provider:     provider,
	}
}

func (s *StreamingReversalReader) Read(p []byte) (int, error) {
	if s.outBuffer.Len() > 0 {
		return s.outBuffer.Read(p)
	}
	if s.eof {
		return 0, io.EOF
	}

	if s.scanner.Scan() {
		line := s.scanner.Text()
		for _, modifiedLine := range s.processLine(line) {
			s.outBuffer.WriteString(modifiedLine + "\n")
		}
		return s.outBuffer.Read(p)
	}

	if err := s.scanner.Err(); err != nil {
		return 0, err
	}

	s.eof = true
	for _, line := range s.flushPendingLines() {
		s.outBuffer.WriteString(line + "\n")
	}
	if s.outBuffer.Len() > 0 {
		return s.outBuffer.Read(p)
	}

	return 0, io.EOF
}

func (s *StreamingReversalReader) Close() error {
	return s.originalBody.Close()
}

func rewriteMapString(data map[string]interface{}, key string, transform func(string) string) bool {
	value, ok := data[key].(string)
	if !ok {
		return false
	}
	data[key] = transform(value)
	return true
}

func rewriteGenericTextFields(data map[string]interface{}, transform func(string) string) bool {
	rewritten := false
	for _, key := range []string{"text", "content", "completion"} {
		if rewriteMapString(data, key, transform) {
			rewritten = true
		}
	}
	return rewritten
}

func rewriteOpenAIText(data map[string]interface{}, transform func(string) string) bool {
	choices, ok := data["choices"].([]interface{})
	if !ok {
		return false
	}
	rewritten := false
	for _, rawChoice := range choices {
		choice, ok := rawChoice.(map[string]interface{})
		if !ok {
			continue
		}
		if delta, ok := choice["delta"].(map[string]interface{}); ok {
			if rewriteMapString(delta, "content", transform) {
				rewritten = true
			}
		}
		if message, ok := choice["message"].(map[string]interface{}); ok {
			if rewriteMapString(message, "content", transform) {
				rewritten = true
			}
		}
		if rewriteMapString(choice, "text", transform) {
			rewritten = true
		}
	}
	return rewritten
}

func rewriteAnthropicText(data map[string]interface{}, transform func(string) string) bool {
	rewritten := false
	if delta, ok := data["delta"].(map[string]interface{}); ok {
		if rewriteMapString(delta, "text", transform) {
			rewritten = true
		}
	}
	if rewriteMapString(data, "completion", transform) {
		rewritten = true
	}
	if rewriteMapString(data, "text", transform) {
		rewritten = true
	}
	return rewritten
}

func rewriteGeminiText(data map[string]interface{}, transform func(string) string) bool {
	candidates, ok := data["candidates"].([]interface{})
	if !ok {
		return false
	}
	rewritten := false
	for _, rawCandidate := range candidates {
		candidate, ok := rawCandidate.(map[string]interface{})
		if !ok {
			continue
		}
		content, ok := candidate["content"].(map[string]interface{})
		if !ok {
			continue
		}
		parts, ok := content["parts"].([]interface{})
		if !ok {
			continue
		}
		for _, rawPart := range parts {
			part, ok := rawPart.(map[string]interface{})
			if !ok {
				continue
			}
			if rewriteMapString(part, "text", transform) {
				rewritten = true
			}
		}
	}
	return rewritten
}

func rewriteNestedString(data map[string]interface{}, path []string, transform func(string) string) bool {
	current := data
	for _, key := range path[:len(path)-1] {
		next, ok := current[key].(map[string]interface{})
		if !ok {
			return false
		}
		current = next
	}
	return rewriteMapString(current, path[len(path)-1], transform)
}

func rewriteTextBlocks(rawBlocks interface{}, transform func(string) string) bool {
	blocks, ok := rawBlocks.([]interface{})
	if !ok {
		return false
	}
	rewritten := false
	for _, rawBlock := range blocks {
		block, ok := rawBlock.(map[string]interface{})
		if !ok {
			continue
		}
		if rewriteMapString(block, "text", transform) {
			rewritten = true
		}
	}
	return rewritten
}

func rewriteCohereText(data map[string]interface{}, transform func(string) string) bool {
	rewritten := false
	if rewriteMapString(data, "text", transform) {
		rewritten = true
	}
	if rewriteMapString(data, "message", transform) {
		rewritten = true
	}
	if rewriteMapString(data, "response", transform) {
		rewritten = true
	}
	if rewriteNestedString(data, []string{"delta", "text"}, transform) {
		rewritten = true
	}
	if rewriteNestedString(data, []string{"delta", "message", "content", "text"}, transform) {
		rewritten = true
	}
	if delta, ok := data["delta"].(map[string]interface{}); ok {
		if message, ok := delta["message"].(map[string]interface{}); ok {
			if rewriteTextBlocks(message["content"], transform) {
				rewritten = true
			}
		}
	}
	if message, ok := data["message"].(map[string]interface{}); ok {
		if rewriteMapString(message, "content", transform) {
			rewritten = true
		}
		if rewriteTextBlocks(message["content"], transform) {
			rewritten = true
		}
	}
	return rewritten
}

func rewriteDeltaText(chunk []byte, provider string, transform func(string) string) ([]byte, bool, error) {
	var data map[string]interface{}
	if err := json.Unmarshal(chunk, &data); err != nil {
		return nil, false, err
	}

	rewritten := false
	switch strings.ToLower(provider) {
	case "openai", "azure_openai":
		rewritten = rewriteOpenAIText(data, transform)
	case "anthropic":
		rewritten = rewriteAnthropicText(data, transform)
	case "cohere":
		rewritten = rewriteCohereText(data, transform)
	case "gemini":
		rewritten = rewriteGeminiText(data, transform)
	}

	if !rewritten {
		rewritten = rewriteGenericTextFields(data, transform)
	}
	if !rewritten {
		return nil, false, nil
	}

	modifiedJSON, err := json.Marshal(data)
	return modifiedJSON, true, err
}

func splitSSEDataLine(line string) (prefix string, payload string, ok bool) {
	if !strings.HasPrefix(line, "data:") {
		return "", "", false
	}
	payload = strings.TrimPrefix(line, "data:")
	if strings.HasPrefix(payload, " ") {
		return "data: ", strings.TrimPrefix(payload, " "), true
	}
	return "data:", payload, true
}

func syntheticDeltaPayload(provider string, text string) []byte {
	var data map[string]interface{}
	switch strings.ToLower(provider) {
	case "openai", "azure_openai":
		data = map[string]interface{}{
			"choices": []interface{}{
				map[string]interface{}{
					"delta": map[string]interface{}{"content": text},
				},
			},
		}
	case "anthropic":
		data = map[string]interface{}{
			"type":  "content_block_delta",
			"delta": map[string]interface{}{"type": "text_delta", "text": text},
		}
	case "gemini":
		data = map[string]interface{}{
			"candidates": []interface{}{
				map[string]interface{}{
					"content": map[string]interface{}{
						"parts": []interface{}{map[string]interface{}{"text": text}},
					},
				},
			},
		}
	case "cohere":
		data = map[string]interface{}{
			"type": "content-delta",
			"delta": map[string]interface{}{
				"message": map[string]interface{}{
					"content": map[string]interface{}{
						"type": "text",
						"text": text,
					},
				},
			},
		}
	default:
		data = map[string]interface{}{"text": text}
	}
	payload, err := json.Marshal(data)
	if err != nil {
		return []byte(text)
	}
	return payload
}

func (s *StreamingReversalReader) flushPendingLines() []string {
	flushedText := s.reverser.Flush()
	if s.outbound != nil {
		flushedText = s.outbound.ProcessChunk(s.ctx, flushedText) + s.outbound.Flush(s.ctx)
	}
	if flushedText == "" {
		return nil
	}
	if !s.sawStructured {
		return []string{flushedText}
	}
	payload := string(syntheticDeltaPayload(s.provider, flushedText))
	if s.lastSSEPrefix != "" {
		return []string{s.lastSSEPrefix + payload}
	}
	return []string{payload}
}

func (s *StreamingReversalReader) processLine(line string) []string {
	if prefix, payload, ok := splitSSEDataLine(line); ok {
		if strings.TrimSpace(payload) == "[DONE]" {
			lines := s.flushPendingLines()
			return append(lines, line)
		}
		modifiedJSON, ok, err := rewriteDeltaText([]byte(payload), s.provider, func(text string) string {
			processed := s.reverser.ProcessChunk(text)
			if s.outbound != nil {
				return s.outbound.ProcessChunk(s.ctx, processed)
			}
			return processed
		})
		if err != nil || !ok {
			return []string{line}
		}
		s.lastSSEPrefix = prefix
		s.sawStructured = true
		return []string{prefix + string(modifiedJSON)}
	}

	if strings.HasPrefix(strings.TrimSpace(line), "{") {
		modifiedJSON, ok, err := rewriteDeltaText([]byte(line), s.provider, func(text string) string {
			processed := s.reverser.ProcessChunk(text)
			if s.outbound != nil {
				return s.outbound.ProcessChunk(s.ctx, processed)
			}
			return processed
		})
		if err != nil || !ok {
			return []string{line}
		}
		s.lastSSEPrefix = ""
		s.sawStructured = true
		return []string{string(modifiedJSON)}
	}

	return []string{line}
}

// Latency Profiling Wrapper
func ProfileRedaction(label string, fn func()) time.Duration {
	start := time.Now()
	fn()
	duration := time.Since(start)
	log.Printf("[PROFILER] %s took %v", label, duration)
	return duration
}
