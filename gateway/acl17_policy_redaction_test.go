package main

import (
	"bytes"
	"errors"
	"io"
	"log"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestACL17WarnPolicyIsTenantConfigurableAndRedacted(t *testing.T) {
	warnPolicy, err := ValidatePolicyYAML(`
regex_rules:
  - name: employee_email
    entity: email
    pattern: '(?i)[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}'
    action: warn
    reason: Tenant warning policy
`)
	if err != nil {
		t.Fatalf("warn policy should be valid: %v", err)
	}
	blockPolicy, err := ValidatePolicyYAML(`
regex_rules:
  - name: employee_email
    entity: email
    pattern: '(?i)[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}'
    action: block
    reason: Tenant blocking policy
`)
	if err != nil {
		t.Fatalf("block policy should be valid: %v", err)
	}

	prompts := []string{"Contact vidhi@example.com"}
	warningMatch, err := FindWarningRuleMatch(warnPolicy, prompts)
	if err != nil || warningMatch == nil {
		t.Fatalf("expected tenant warning match, match=%v err=%v", warningMatch, err)
	}
	blockMatch, err := FindBlockingRuleMatch(blockPolicy, prompts)
	if err != nil || blockMatch == nil {
		t.Fatalf("expected tenant block match, match=%v err=%v", blockMatch, err)
	}
	if match, _ := FindBlockingRuleMatch(warnPolicy, prompts); match != nil {
		t.Fatal("warning tenant policy must not be treated as block")
	}
	if match, _ := FindWarningRuleMatch(blockPolicy, prompts); match != nil {
		t.Fatal("blocking tenant policy must not be treated as warning")
	}

	redactionRules := RedactionRulesForEgress(warnPolicy)
	if len(redactionRules) != 1 || redactionRules[0].normalizedAction() != "warn" {
		t.Fatalf("warning content must be redacted before egress: %#v", redactionRules)
	}
	if got := RedactionRulesForEgress(blockPolicy); len(got) != 0 {
		t.Fatalf("blocking rules must not enter the redaction path: %#v", got)
	}
}

func TestACL17WarningAuditEvidenceContainsHashNotRawValue(t *testing.T) {
	rawEmail := "vidhi@example.com"
	config := &PolicyConfig{RegexRules: []RegexRule{{
		Name:    "employee email",
		Entity:  "email address",
		Pattern: `(?i)[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}`,
		Action:  "warn",
	}}}
	match, err := FindWarningRuleMatch(config, []string{"Contact " + rawEmail})
	if err != nil || match == nil {
		t.Fatalf("expected warning match, match=%v err=%v", match, err)
	}

	trace := strings.Join(PolicyRuleAuditTrace(match, "warn"), " ")
	if strings.Contains(trace, rawEmail) {
		t.Fatalf("audit trace leaked raw sensitive value: %s", trace)
	}
	if !strings.Contains(trace, "match_sha256=") || !strings.Contains(trace, "entity=email_address") {
		t.Fatalf("audit trace missing safe evidence: %s", trace)
	}
}

func TestACL17ApprovedPIIAndPHIFixturesAreDetected(t *testing.T) {
	fixture := "Patient Jane Doe at vidhi@example.com was diagnosed in hospital; SSN 123-45-6789."
	results := fallbackAnalyze(fixture, nil)
	entities := make(map[string]bool)
	for _, result := range results {
		entities[result.EntityType] = true
	}
	for _, required := range []string{"EMAIL_ADDRESS", "US_SSN", "HEALTH_DATA", "PERSON"} {
		if !entities[required] {
			t.Errorf("expected %s detection in approved fixture; got %#v", required, entities)
		}
	}
}

func TestACL17RedactedBodyIsPreparedBeforeProviderEgress(t *testing.T) {
	rawEmail := "vidhi@example.com"
	request := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(`{"message":"`+rawEmail+`"}`))
	original := []string{"Contact " + rawEmail}
	redacted := []string{"Contact [REDACTED_EMAIL_ADDRESS_test]"}
	rebuilder := func(prompts []string) ([]byte, error) {
		return []byte(`{"message":"` + prompts[0] + `"}`), nil
	}

	if err := applyRedactedPromptsToRequest(request, original, redacted, rebuilder); err != nil {
		t.Fatalf("prepare redacted request: %v", err)
	}
	body, err := io.ReadAll(request.Body)
	if err != nil {
		t.Fatalf("read rebuilt body: %v", err)
	}
	if bytes.Contains(body, []byte(rawEmail)) {
		t.Fatalf("provider request retained raw sensitive value: %s", body)
	}
	if !bytes.Contains(body, []byte("[REDACTED_EMAIL_ADDRESS_test]")) {
		t.Fatalf("provider request missing redaction token: %s", body)
	}
}

func TestACL17RequestRebuildFailureReturnsError(t *testing.T) {
	request := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(`{}`))
	err := applyRedactedPromptsToRequest(
		request,
		[]string{"vidhi@example.com"},
		[]string{"[REDACTED_EMAIL_ADDRESS_test]"},
		func([]string) ([]byte, error) { return nil, errors.New("synthetic rebuild failure") },
	)
	if err == nil || !strings.Contains(err.Error(), "rebuild redacted request body") {
		t.Fatalf("expected fail-closed rebuild error, got %v", err)
	}
}

func TestACL17DebugLoggingNeverIncludesRawPrompts(t *testing.T) {
	t.Setenv("GATEWAY_DEBUG_PROMPTS", "true")
	rawEmail := "vidhi@example.com"
	var output bytes.Buffer
	previousWriter := log.Writer()
	previousFlags := log.Flags()
	log.SetOutput(&output)
	log.SetFlags(0)
	defer func() {
		log.SetOutput(previousWriter)
		log.SetFlags(previousFlags)
	}()

	logRedactionDebugMetadata(
		"req-acl17",
		ProviderOpenAI,
		[]string{"Contact " + rawEmail},
		[]string{"Contact [REDACTED_EMAIL_ADDRESS_test]"},
		1,
	)

	logged := output.String()
	if strings.Contains(logged, rawEmail) {
		t.Fatalf("debug log leaked raw sensitive value: %s", logged)
	}
	for _, expected := range []string{"request_id=req-acl17", "prompt_count=1", "changed=true", "token_count=1"} {
		if !strings.Contains(logged, expected) {
			t.Errorf("debug metadata missing %q: %s", expected, logged)
		}
	}
}

func TestACL17PolicyActionMetrics(t *testing.T) {
	before := PolicyActionMetricsSnapshot()
	RecordPolicyAction("block")
	RecordPolicyAction("warn")
	RecordPolicyAction("redact")
	RecordPolicyAction("fail_closed")
	after := PolicyActionMetricsSnapshot()

	for _, metric := range []string{
		"authclaw_gateway_policy_block_total",
		"authclaw_gateway_policy_warn_total",
		"authclaw_gateway_policy_redact_total",
		"authclaw_gateway_policy_fail_closed_total",
	} {
		if after[metric] != before[metric]+1 {
			t.Errorf("%s increment = %d, want %d", metric, after[metric], before[metric]+1)
		}
	}
}
