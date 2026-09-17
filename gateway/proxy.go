package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"time"
)

// ProxyServer manages LLM provider routing and proxying
type ProxyServer struct {
	OpenAIBaseURL      string
	AnthropicBaseURL   string
	CohereBaseURL      string
	AzureOpenAIBaseURL string
	GeminiBaseURL      string
	BedrockBaseURL     string
}

var providerProxyTransport = providerReadTimeout(func() http.RoundTripper {
	transport, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return http.DefaultTransport
	}
	clone := transport.Clone()
	clone.MaxIdleConns = 200
	clone.MaxIdleConnsPerHost = 100
	return configureProviderTransport(clone)
}(), 30*time.Second)

func NewProxyServer() *ProxyServer {
	openAIBase := os.Getenv("OPENAI_BASE_URL")
	if openAIBase == "" {
		openAIBase = "https://api.openai.com"
	}
	anthropicBase := os.Getenv("ANTHROPIC_BASE_URL")
	if anthropicBase == "" {
		anthropicBase = "https://api.anthropic.com"
	}
	cohereBase := os.Getenv("COHERE_BASE_URL")
	if cohereBase == "" {
		cohereBase = "https://api.cohere.ai"
	}
	azureBase := os.Getenv("AZURE_OPENAI_BASE_URL")
	geminiBase := os.Getenv("GEMINI_BASE_URL")
	if geminiBase == "" {
		geminiBase = "https://generativelanguage.googleapis.com"
	}
	bedrockBase := ""
	if isBedrockEnabled() {
		bedrockBase = BedrockEndpoint()
	}
	return &ProxyServer{
		OpenAIBaseURL:      openAIBase,
		AnthropicBaseURL:   anthropicBase,
		CohereBaseURL:      cohereBase,
		AzureOpenAIBaseURL: azureBase,
		GeminiBaseURL:      geminiBase,
		BedrockBaseURL:     bedrockBase,
	}
}

// RouteRequest determines the target provider base URL based on the request
func (p *ProxyServer) RouteRequest(r *http.Request) string {
	provider := ProviderForRequest(r)
	if baseURL := providerBaseURL(p, provider); baseURL != "" {
		return baseURL
	}
	if provider == ProviderBedrock && p.BedrockBaseURL != "" {
		return p.BedrockBaseURL
	}
	return ""
}

type responseWriter struct {
	http.ResponseWriter
	status int
}

func (rw *responseWriter) Unwrap() http.ResponseWriter {
	return rw.ResponseWriter
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.status = code
	rw.ResponseWriter.WriteHeader(code)
}

func generateID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "unknown"
	}
	return hex.EncodeToString(b)
}

func sameStringSlice(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

func requiresTenantProviderCredential(provider string) bool {
	switch NormalizeProvider(provider) {
	case ProviderOpenAI, ProviderAnthropic, ProviderCohere, ProviderAzureOpenAI, ProviderGemini:
		return true
	default:
		return false
	}
}

func supportsSensitiveDataProtection(provider string) bool {
	switch NormalizeProvider(provider) {
	case ProviderOpenAI, ProviderAnthropic, ProviderCohere, ProviderAzureOpenAI, ProviderGemini, ProviderBedrock:
		return true
	default:
		return false
	}
}

func applyRedactedPromptsToRequest(
	request *http.Request,
	originalPrompts []string,
	redactedPrompts []string,
	rebuilder func([]string) ([]byte, error),
) error {
	if sameStringSlice(originalPrompts, redactedPrompts) {
		return nil
	}
	if rebuilder == nil {
		return fmt.Errorf("request body rebuilder is unavailable")
	}
	newBody, err := rebuilder(redactedPrompts)
	if err != nil {
		return fmt.Errorf("rebuild redacted request body: %w", err)
	}
	request.Body = io.NopCloser(bytes.NewBuffer(newBody))
	request.ContentLength = int64(len(newBody))
	request.Header.Set("Content-Length", fmt.Sprintf("%d", len(newBody)))
	return nil
}

func logRedactionDebugMetadata(requestID, provider string, originalPrompts, redactedPrompts []string, tokenCount int) {
	if !envBool("GATEWAY_DEBUG_PROMPTS", false) {
		return
	}
	log.Printf(
		"[DEBUG] redaction_metadata request_id=%s provider=%s prompt_count=%d changed=%t token_count=%d",
		requestID,
		provider,
		len(originalPrompts),
		!sameStringSlice(originalPrompts, redactedPrompts),
		tokenCount,
	)
}

func (p *ProxyServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Extract tenant ID and request ID from context (injected by AuthMiddleware)
	tenantID, _ := r.Context().Value(TenantIDContextKey).(string)
	requestID, _ := r.Context().Value(RequestIDContextKey).(string)
	requesterID, _ := r.Context().Value(UserIDContextKey).(string)

	// Determine provider
	provider := ProviderForRequest(r)
	if provider == ProviderBedrock {
		if _, _, err := bedrockEntitlement(tenantID, ExtractBedrockModel(r.URL.Path)); err != nil {
			if !emitRequiredDecision(w, r, &AuditEvent{ID: generateID(), RequestID: requestID, Timestamp: time.Now(), TenantID: tenantID, Provider: provider, Action: "block", DecisionReason: "Bedrock entitlement denied", ResponseStatus: http.StatusForbidden}, "bedrock_entitlement_denied") {
				return
			}
			writeGatewayError(w, http.StatusForbidden, "BedrockNotAuthorized", "Bedrock is not enabled for this tenant and model.")
			return
		}
	}
	targetURLStr := p.RouteRequest(r)

	providerCredential, credentialErr := LoadProviderCredential(r.Context(), tenantID, provider)
	if credentialErr != nil {
		log.Printf("Provider credential load failed: %v", credentialErr)
		queueNotification(r.Context(), tenantID, "", "gateway_api_key_issue", "warning", "Provider credential unavailable", "The saved provider credential could not be decrypted. Verify that backend and gateway use the same envelope key.", "/connect")
		if !emitRequiredDecision(w, r, &AuditEvent{
			ID: generateID(), RequestID: requestID, Timestamp: time.Now(),
			TenantID: tenantID, Action: "block", DecisionReason: "Provider credential unavailable",
			Provider: provider, RequestSize: int(r.ContentLength), ResponseStatus: http.StatusBadGateway, DurationMs: 0,
		}, "provider_credential_unavailable") {
			return
		}
		writeGatewayError(w, http.StatusBadGateway, "ProviderCredentialUnavailable", "Provider credential could not be loaded.")
		return
	}
	if tenantID != "" && requiresTenantProviderCredential(provider) && (providerCredential == nil || providerCredential.APIKey == "") {
		queueNotification(r.Context(), tenantID, "", "gateway_api_key_issue", "warning", "Provider credential missing", "Save an active provider API key before sending gateway traffic.", "/connect")
		if !emitRequiredDecision(w, r, &AuditEvent{
			ID: generateID(), RequestID: requestID, Timestamp: time.Now(),
			TenantID: tenantID, Action: "block", DecisionReason: "Provider credential missing",
			Provider: provider, ResponseStatus: http.StatusBadGateway, DurationMs: 0,
		}, "provider_credential_missing") {
			return
		}
		writeGatewayError(w, http.StatusBadGateway, "ProviderCredentialMissing", "Save an active provider API key before sending gateway traffic.")
		return
	}
	if provider != ProviderBedrock && providerCredential != nil && providerCredential.Endpoint != "" {
		targetURLStr = providerCredential.Endpoint
	}
	if targetURLStr == "" {
		if !emitRequiredDecision(w, r, &AuditEvent{
			ID: generateID(), RequestID: requestID, Timestamp: time.Now(), TenantID: tenantID,
			Action: "block", DecisionReason: "Provider endpoint not configured", Provider: provider,
			ResponseStatus: http.StatusBadGateway,
		}, "provider_endpoint_missing") {
			return
		}
		http.Error(w, "Provider endpoint not configured", http.StatusBadGateway)
		return
	}

	// Extract and normalize request details
	var model string
	var promptCount int
	var originalPrompts []string
	normalized, rebuilder, err := ExtractAndNormalize(r, provider)
	if err == nil && normalized != nil {
		model = normalized.Model
		promptCount = len(normalized.Prompts)
		originalPrompts = make([]string, len(normalized.Prompts))
		copy(originalPrompts, normalized.Prompts)
	}
	if err != nil && tenantID != "" && supportsSensitiveDataProtection(provider) {
		log.Printf("[GATEWAY] request normalization failed request_id=%s provider=%s err=%v", requestID, provider, err)
		RecordPolicyAction("fail_closed")
		if !emitRequiredDecision(w, r, &AuditEvent{
			ID: generateID(), RequestID: requestID, Timestamp: time.Now(),
			TenantID: tenantID, Action: "block",
			DecisionReason: "Request normalization failed before sensitive-data inspection",
			Provider:       provider, RequestSize: int(r.ContentLength),
			ResponseStatus: http.StatusBadRequest, DurationMs: 0,
			FrameworksAffected: []string{"GDPR", "SOC2"},
			ExecutionTrace:     []string{"stage=normalize", "result=fail_closed"},
		}, "request_normalization_failed") {
			return
		}
		writeGatewayError(w, http.StatusBadRequest, "SensitiveDataInspectionFailed", "Request blocked: request body could not be inspected safely.")
		return
	}
	if routeErr := ValidateProviderRoute(provider, r, targetURLStr, model); routeErr != nil {
		if !emitRequiredDecision(w, r, &AuditEvent{
			ID: generateID(), RequestID: requestID, Timestamp: time.Now(),
			TenantID: tenantID, Action: "block", DecisionReason: routeErr.Error(),
			Provider: provider, Model: model, PromptCount: promptCount,
			RequestSize: int(r.ContentLength), ResponseStatus: http.StatusBadRequest, DurationMs: 0,
		}, "provider_route_invalid") {
			return
		}
		writeGatewayError(w, http.StatusBadRequest, "ProviderRouteInvalid", routeErr.Error())
		return
	}

	// Load policy before any pre-egress rule checks. A malformed or unavailable
	// tenant policy defaults to deny rather than silently bypassing gateway rules.
	config, policyID, policyLoadErr := LoadPolicyWithCache(r.Context(), tenantID)
	if policyLoadErr != nil {
		log.Printf("[POLICY-ERROR] Early policy load failed: %v", policyLoadErr)
		if !emitRequiredDecision(w, r, &AuditEvent{
			ID: generateID(), RequestID: requestID, Timestamp: time.Now(),
			TenantID: tenantID, PolicyID: policyID, Action: "block",
			DecisionReason: "Request blocked: policy loading or parsing error",
			Provider:       provider, Model: model, PromptCount: promptCount,
			RequestSize: int(r.ContentLength), ResponseStatus: http.StatusForbidden, DurationMs: 0,
		}, "policy_load_failed") {
			return
		}
		writeGatewayError(w, http.StatusForbidden, "PolicyEvaluationFailed", "Request blocked: policy loading or parsing error")
		return
	}
	var customRules []RegexRule
	if config != nil {
		customRules = RedactionRulesForEgress(config)
	}

	if normalized != nil && len(normalized.Prompts) > 0 {
		blockMatch, blockMatchErr := FindBlockingRuleMatch(config, normalized.Prompts)
		if blockMatchErr != nil {
			log.Printf("Custom block rule evaluation failed: %v", blockMatchErr)
			if !emitRequiredDecision(w, r, &AuditEvent{
				ID: generateID(), RequestID: requestID, Timestamp: time.Now(),
				TenantID: tenantID, PolicyID: policyID, Action: "block",
				DecisionReason: "Custom block policy evaluation failed", Provider: provider, Model: model,
				PromptCount: promptCount, RequestSize: int(r.ContentLength),
				ResponseStatus: http.StatusForbidden, DurationMs: 0,
			}, "custom_block_evaluation_failed") {
				return
			}
			http.Error(w, "Request blocked: custom policy evaluation failed", http.StatusForbidden)
			return
		}
		if blockMatch != nil {
			reason := PolicyRuleDecisionReason(blockMatch, "block")
			RecordPolicyAction("block")
			queueNotification(r.Context(), tenantID, "", "policy_violation_block", "critical", "Policy blocked request", reason, "/audit")
			if !emitRequiredDecision(w, r, &AuditEvent{
				ID: generateID(), RequestID: requestID, Timestamp: time.Now(),
				TenantID: tenantID, PolicyID: policyID, Action: "block",
				DecisionReason: reason, Provider: provider, Model: model,
				PromptCount: promptCount, RequestSize: int(r.ContentLength),
				ResponseStatus: http.StatusForbidden, DurationMs: 0,
				FrameworksAffected: []string{"GDPR", "SOC2"},
				ExecutionTrace:     PolicyRuleAuditTrace(blockMatch, "block"),
			}, "custom_policy_block") {
				return
			}
			writeGatewayError(w, http.StatusForbidden, "PolicyBlocked", reason)
			return
		}
	}

	// HITL gate for high-risk custom redaction policies.
	// This runs before redaction and before provider egress. The prompt itself is not
	// stored in the approval payload; only hashes and policy metadata are stored.
	finalAllowReason := "Allowed"
	if normalized != nil && len(normalized.Prompts) > 0 {
		warningMatch, warningMatchErr := FindWarningRuleMatch(config, normalized.Prompts)
		if warningMatchErr != nil {
			log.Printf("Custom warning rule evaluation failed: %v", warningMatchErr)
			RecordPolicyAction("fail_closed")
			if !emitRequiredDecision(w, r, &AuditEvent{
				ID: generateID(), RequestID: requestID, Timestamp: time.Now(),
				TenantID: tenantID, PolicyID: policyID, Action: "block",
				DecisionReason: "Warning policy evaluation failed", Provider: provider, Model: model,
				PromptCount: promptCount, RequestSize: int(r.ContentLength),
				ResponseStatus: http.StatusForbidden, DurationMs: 0,
				FrameworksAffected: []string{"GDPR", "SOC2"},
				ExecutionTrace:     []string{"stage=warn", "result=fail_closed"},
			}, "warning_policy_evaluation_failed") {
				return
			}
			http.Error(w, "Request blocked: warning policy evaluation failed", http.StatusForbidden)
			return
		}
		if warningMatch != nil {
			reason := PolicyRuleDecisionReason(warningMatch, "warn")
			RecordPolicyAction("warn")
			finalAllowReason = "Allowed with policy warning and redaction"
			w.Header().Set("X-AuthClaw-Policy-Action", "warn")
			w.Header().Set("X-AuthClaw-Policy-Warning", "true")
			queueNotification(r.Context(), tenantID, "", "policy_violation_warn", "warning", "Policy warning applied", reason, "/audit")
			emitAuditTelemetry(r.Context(), &AuditEvent{
				ID: generateID(), RequestID: requestID, Timestamp: time.Now(),
				TenantID: tenantID, PolicyID: policyID, Action: "warn",
				DecisionReason: reason, Provider: provider, Model: model,
				PromptCount: promptCount, RequestSize: int(r.ContentLength),
				ResponseStatus: 0, DurationMs: 0,
				FrameworksAffected: []string{"GDPR", "SOC2"},
				ExecutionTrace:     PolicyRuleAuditTrace(warningMatch, "warn"),
			}, "policy_warning")
		}
	}
	if normalized != nil && len(normalized.Prompts) > 0 {
		approvalMatch, approvalMatchErr := FindApprovalRuleMatch(config, normalized.Prompts)
		if approvalMatchErr != nil {
			log.Printf("HITL rule evaluation failed: %v", approvalMatchErr)
			if !emitRequiredDecision(w, r, &AuditEvent{
				ID: generateID(), RequestID: requestID, Timestamp: time.Now(),
				TenantID: tenantID, PolicyID: policyID, Action: "block",
				DecisionReason: "HITL policy evaluation failed", Provider: provider, Model: model,
				PromptCount: promptCount, RequestSize: int(r.ContentLength),
				ResponseStatus: http.StatusForbidden, DurationMs: 0,
			}, "approval_policy_evaluation_failed") {
				return
			}
			http.Error(w, "Request blocked: approval policy evaluation failed", http.StatusForbidden)
			return
		}
		if approvalMatch != nil {
			approvalID, timeout, approvalErr := CreateGatewayApproval(
				r.Context(), tenantID, requesterID, requestID, provider, model, normalized.Prompts, approvalMatch,
			)
			if approvalErr != nil {
				log.Printf("Failed to create gateway approval: %v", approvalErr)
				if !emitRequiredDecision(w, r, &AuditEvent{
					ID: generateID(), RequestID: requestID, Timestamp: time.Now(),
					TenantID: tenantID, PolicyID: policyID, Action: "block",
					DecisionReason: "Failed to create HITL approval", Provider: provider, Model: model,
					PromptCount: promptCount, RequestSize: int(r.ContentLength),
					ResponseStatus: http.StatusForbidden, DurationMs: 0,
				}, "approval_creation_failed") {
					return
				}
				http.Error(w, "Request blocked: failed to create human approval", http.StatusForbidden)
				return
			}

			log.Printf("[HITL] approval_id=%s request_id=%s rule=%s timeout=%s", approvalID, requestID, approvalMatch.Rule.Name, timeout)
			status, waitErr := WaitForGatewayApproval(r.Context(), tenantID, approvalID, timeout)
			if waitErr != nil {
				log.Printf("Gateway approval wait failed: %v", waitErr)
				if !emitRequiredDecision(w, r, &AuditEvent{
					ID: generateID(), RequestID: requestID, Timestamp: time.Now(),
					TenantID: tenantID, PolicyID: policyID, Action: "block",
					DecisionReason: "HITL approval wait failed", Provider: provider, Model: model,
					PromptCount: promptCount, RequestSize: int(r.ContentLength),
					ResponseStatus: http.StatusForbidden, DurationMs: 0,
				}, "approval_wait_failed") {
					return
				}
				http.Error(w, "Request blocked: human approval wait failed", http.StatusForbidden)
				return
			}
			if status != "APPROVED" {
				if !emitRequiredDecision(w, r, &AuditEvent{
					ID: generateID(), RequestID: requestID, Timestamp: time.Now(),
					TenantID: tenantID, PolicyID: policyID, Action: "block",
					DecisionReason: fmt.Sprintf("HITL approval %s", status), Provider: provider, Model: model,
					PromptCount: promptCount, RequestSize: int(r.ContentLength),
					ResponseStatus: http.StatusForbidden, DurationMs: 0,
				}, "approval_not_granted") {
					return
				}
				writeJSON(w, http.StatusForbidden, gatewayErrorResponse{
					Error: "ApprovalRequired", Message: fmt.Sprintf("Request blocked: HITL approval status is %s", status), ApprovalID: approvalID,
				})
				return
			}
			if !emitRequiredDecision(w, r, &AuditEvent{
				ID: generateID(), RequestID: requestID, Timestamp: time.Now(),
				TenantID: tenantID, PolicyID: policyID, Action: "approval_allow",
				DecisionReason: "HITL approved: " + PolicyRuleDecisionReason(approvalMatch, "require_approval"),
				Provider:       provider, Model: model, PromptCount: promptCount,
				RequestSize: int(r.ContentLength), ResponseStatus: http.StatusOK, DurationMs: 0,
			}, "approval_allow") {
				return
			}
			finalAllowReason = "HITL approved: " + PolicyRuleDecisionReason(approvalMatch, "require_approval")
		}
	}

	// Inbound Prompt Redaction
	var tokenMap map[string]string
	if tenantID != "" && supportsSensitiveDataProtection(provider) {
		if normalized != nil && len(normalized.Prompts) > 0 {
			var redactErr error
			var redactedPrompts []string
			redactStart := time.Now()
			redactedPrompts, tokenMap, redactErr = RedactPrompts(r.Context(), tenantID, normalized.Prompts, customRules)
			redactDurationMs := time.Since(redactStart).Milliseconds()
			if redactErr == nil {
				if time.Duration(redactDurationMs)*time.Millisecond >= presidioSlowLogThreshold() {
					log.Printf("[REDACTION] status=slow_complete duration_ms=%d request_id=%s provider=%s prompt_count=%d token_count=%d", redactDurationMs, requestID, provider, len(normalized.Prompts), len(tokenMap))
				}
				logRedactionDebugMetadata(requestID, provider, normalized.Prompts, redactedPrompts, len(tokenMap))
				if len(tokenMap) > 0 {
					RecordPolicyAction("redact")
					if finalAllowReason == "Allowed" {
						finalAllowReason = "Allowed after redaction"
					} else if !strings.Contains(strings.ToLower(finalAllowReason), "redact") {
						finalAllowReason += " + redacted"
					}
					emitAuditTelemetry(r.Context(), &AuditEvent{
						ID:                 generateID(),
						RequestID:          requestID,
						Timestamp:          time.Now(),
						TenantID:           tenantID,
						PolicyID:           policyID,
						Action:             "redact",
						DecisionReason:     "Prompt redaction applied",
						Provider:           provider,
						Model:              model,
						PromptCount:        promptCount,
						RequestSize:        int(r.ContentLength),
						ResponseStatus:     0,
						DurationMs:         redactDurationMs,
						FrameworksAffected: []string{"GDPR", "SOC2"},
						ExecutionTrace:     []string{"stage=pre_egress", "result=redacted"},
					}, "prompt_redaction")
				}
				if rebuildErr := applyRedactedPromptsToRequest(r, normalized.Prompts, redactedPrompts, rebuilder); rebuildErr != nil {
					log.Printf("[REDACTION] status=rebuild_failed request_id=%s provider=%s err=%v", requestID, provider, rebuildErr)
					RecordPolicyAction("fail_closed")
					if !emitRequiredDecision(w, r, &AuditEvent{
						ID: generateID(), RequestID: requestID, Timestamp: time.Now(),
						TenantID: tenantID, PolicyID: policyID, Action: "block",
						DecisionReason: "Sanitized request rebuild failed", Provider: provider, Model: model,
						PromptCount: promptCount, RequestSize: int(r.ContentLength),
						ResponseStatus: http.StatusForbidden, DurationMs: redactDurationMs,
						FrameworksAffected: []string{"GDPR", "SOC2"},
						ExecutionTrace:     []string{"stage=rebuild", "result=fail_closed"},
					}, "redaction_rebuild_failed") {
						return
					}
					http.Error(w, "Request blocked: sanitized request could not be prepared", http.StatusForbidden)
					return
				}
			} else {
				log.Printf("[REDACTION] status=error duration_ms=%d request_id=%s provider=%s prompt_count=%d err=%v", redactDurationMs, requestID, provider, len(normalized.Prompts), redactErr)
				RecordPolicyAction("fail_closed")
				if !emitRequiredDecision(w, r, &AuditEvent{
					ID: generateID(), RequestID: requestID, Timestamp: time.Now(),
					TenantID: tenantID, PolicyID: policyID, Action: "block",
					DecisionReason: "Sensitive-data redaction failed before provider egress",
					Provider:       provider, Model: model, PromptCount: promptCount,
					RequestSize: int(r.ContentLength), ResponseStatus: http.StatusForbidden,
					DurationMs:         redactDurationMs,
					FrameworksAffected: []string{"GDPR", "SOC2"},
					ExecutionTrace:     []string{"stage=redact", "result=fail_closed"},
				}, "redaction_failed") {
					return
				}
				http.Error(w, "Request blocked: sensitive-data redaction failed", http.StatusForbidden)
				return
			}
		}
	}

	// Policy Evaluation
	var topics []string
	for token := range tokenMap {
		if strings.Contains(token, "_HEALTH_DATA_") {
			topics = append(topics, "medical")
			break
		}
	}

	route := r.URL.Path
	allow, reason, polID, evalErr := EvaluatePolicy(r.Context(), tenantID, model, route, originalPrompts, topics)
	policyID = polID
	if evalErr != nil {
		log.Printf("Policy evaluation error: %v", evalErr)
	}

	if !allow {
		RecordPolicyAction("block")
		queueNotification(r.Context(), tenantID, "", "policy_violation_block", "critical", "Policy blocked request", reason, "/audit")
		event := &AuditEvent{
			ID:             generateID(),
			RequestID:      requestID,
			Timestamp:      time.Now(),
			TenantID:       tenantID,
			PolicyID:       policyID,
			Action:         "block",
			DecisionReason: reason,
			Provider:       provider,
			Model:          model,
			PromptCount:    promptCount,
			RequestSize:    int(r.ContentLength),
			ResponseStatus: http.StatusForbidden,
			DurationMs:     0,
		}
		if !emitRequiredDecision(w, r, event, "policy_block") {
			return
		}
		writeGatewayError(w, http.StatusForbidden, "Forbidden", reason)
		return
	}
	// Runs AFTER OPA (which can also block on model whitelist).
	// Checked here to prevent any AWS request when daily cap is exceeded.
	if provider == ProviderBedrock {
		body, bodyErr := io.ReadAll(r.Body)
		r.Body = io.NopCloser(bytes.NewReader(body))
		if bodyErr != nil {
			writeGatewayError(w, http.StatusBadRequest, "InvalidBody", "Unable to reserve request budget.")
			return
		}
		if limitErr := ReserveBedrockUsage(r.Context(), tenantID, model, body); limitErr != nil {
			if !emitRequiredDecision(w, r, &AuditEvent{
				ID: generateID(), RequestID: requestID, Timestamp: time.Now(),
				TenantID: tenantID, PolicyID: policyID, Action: "block",
				DecisionReason: "Bedrock budget unavailable or exhausted", Provider: provider, Model: model,
				PromptCount: promptCount, RequestSize: int(r.ContentLength),
				ResponseStatus: http.StatusTooManyRequests, DurationMs: 0,
			}, "bedrock_limit_exceeded") {
				return
			}
			writeGatewayError(w, http.StatusTooManyRequests, "BedrockLimitExceeded", "Bedrock budget unavailable or exhausted.")
			return
		}
	}

	target, err := url.Parse(targetURLStr)
	if err != nil {
		if !emitRequiredDecision(w, r, &AuditEvent{
			ID: generateID(), RequestID: requestID, Timestamp: time.Now(), TenantID: tenantID,
			Action: "block", DecisionReason: "Invalid provider target URL", Provider: provider, Model: model,
			ResponseStatus: http.StatusInternalServerError,
		}, "provider_target_invalid") {
			return
		}
		http.Error(w, "Invalid target URL", http.StatusInternalServerError)
		return
	}
	attemptEvent := &AuditEvent{
		ID: generateID(), RequestID: requestID, Timestamp: time.Now(),
		TenantID: tenantID, PolicyID: policyID, Provider: provider, Model: model,
		PromptCount: promptCount, RequestSize: int(r.ContentLength),
		ExecutionTrace: []string{"stage=pre_egress", "result=authorized"},
	}
	if !requireProviderAttempt(w, r, attemptEvent) {
		return
	}

	// Create reverse proxy
	proxy := httputil.NewSingleHostReverseProxy(target)
	proxy.Transport = providerProxyTransport
	if provider == ProviderBedrock {
		proxy.Transport = bedrockSigningTransport{providerProxyTransport}
	}
	proxy.ErrorHandler = func(rw http.ResponseWriter, req *http.Request, proxyErr error) {
		log.Printf("[PROXY] status=bad_gateway request_id=%s provider=%s target=%s err=%v", requestID, provider, target.String(), proxyErr)
		writeJSON(rw, http.StatusBadGateway, gatewayErrorResponse{
			Error:    "ProviderProxyError",
			Message:  "upstream request failed",
			Provider: provider,
		})
	}

	// Customize director to rewrite target host and request URL
	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)
		req.Header.Del("Accept-Encoding") // ponytail: forced plaintext upstream to skip proxy decompression
		req.Host = target.Host
		req.URL.Scheme = target.Scheme
		req.URL.Host = target.Host
		if provider == ProviderAzureOpenAI && isAzureDeploymentChatPath(target.Path) && !isAzureDeploymentChatPath(r.URL.Path) {
			req.URL.Path = target.Path
			req.URL.RawPath = ""
		}
		ApplyProviderCredential(req, provider, providerCredential, tenantID, target)
		if provider == "anthropic" {
			req.Header.Del("Authorization")
			if providerCredential != nil && providerCredential.APIKey != "" {
				req.Header.Set("x-api-key", providerCredential.APIKey)
				if req.Header.Get("anthropic-version") == "" {
					req.Header.Set("anthropic-version", "2023-06-01")
				}
			}
		} else if provider == "cohere" || provider == "openai" {
			req.Header.Del("Authorization")
			if providerCredential != nil && providerCredential.APIKey != "" {
				req.Header.Set("Authorization", "Bearer "+providerCredential.APIKey)
			}
		} else if provider == "bedrock" {
			// Strip the /bedrock prefix from the path before forwarding
			req.URL.Path = strings.TrimPrefix(req.URL.Path, "/bedrock")
			req.Header.Del("Authorization")

		}
	}

	// Outbound Completion Reversal
	proxy.ModifyResponse = func(resp *http.Response) error {
		if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
			return protectProviderErrorResponse(
				resp,
				int64(envBoundedInt("GATEWAY_RESPONSE_INSPECTION_MAX_BYTES", defaultProviderErrorInspectionBytes, 1024, 4*1024*1024)),
				func(body []byte) ([]byte, error) {
					if tenantID == "" {
						return nil, fmt.Errorf("tenant context is unavailable")
					}
					protected, _, err := redactOutboundText(
						r.Context(), tenantID, string(body), customRules,
						GetRedactionRuntimeConfig(r.Context(), tenantID),
					)
					return []byte(protected), err
				},
			)
		}

		if len(tokenMap) == 0 && tenantID == "" {
			return nil
		}

		contentType := resp.Header.Get("Content-Type")
		if strings.Contains(contentType, "text/event-stream") {
			resp.Body = NewStreamingProtectionReader(r.Context(), resp.Body, tokenMap, provider, tenantID, customRules, GetRedactionRuntimeConfig(r.Context(), tenantID))
		} else {
			body, readErr := io.ReadAll(resp.Body)
			if closeErr := resp.Body.Close(); closeErr != nil && readErr == nil {
				readErr = closeErr
			}
			if readErr != nil {
				return readErr
			}
			protectedBody, _, protectErr := ProtectProviderResponseBody(r.Context(), tenantID, provider, body, tokenMap, customRules, GetRedactionRuntimeConfig(r.Context(), tenantID))
			if protectErr != nil {
				return protectErr
			}
			resp.Body = io.NopCloser(bytes.NewReader(protectedBody))
			resp.ContentLength = int64(len(protectedBody))
			resp.Header.Set("Content-Length", fmt.Sprintf("%d", len(protectedBody)))
			resp.Header.Del("Content-Encoding")
			return nil
		}
		if len(tokenMap) > 0 {
			resp.ContentLength = -1
			resp.Header.Del("Content-Length")
		}
		return nil
	}

	startTime := time.Now()

	// Capture response status code
	wrappedWriter := &responseWriter{ResponseWriter: w, status: http.StatusOK}
	if !gatewayProviderQuota(wrappedWriter, r, provider, model) {
		return
	}
	proxy.ServeHTTP(wrappedWriter, r)

	duration := time.Since(startTime).Milliseconds()

	// Emit Allow Audit Event
	auditAction := "allow"
	if strings.HasPrefix(requestID, "connect-test-") {
		auditAction = "test_request"
	}
	event := &AuditEvent{
		ID:             generateID(),
		RequestID:      requestID,
		Timestamp:      startTime,
		TenantID:       tenantID,
		PolicyID:       policyID,
		Action:         auditAction,
		DecisionReason: finalAllowReason,
		Provider:       provider,
		Model:          model,
		PromptCount:    promptCount,
		RequestSize:    int(r.ContentLength),
		ResponseStatus: wrappedWriter.status,
		DurationMs:     duration,
	}
	emitPostResponseOutcome(r.Context(), r.URL.Path, event)
}
