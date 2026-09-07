package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestStructuredLogWriterRedactsSensitiveValues(t *testing.T) {
	var output bytes.Buffer
	writer := safeJSONLogWriter{destination: &output}
	secret := "sensitive-user@example.com"
	line := "request_id=req-safe trace_id=trace-safe tenant=tenant-secret authorization=Bearer.abc token=topsecret document=clinical-note url=https://admin:password@example.invalid jwt=eyJheader.payload.signature user=" + secret
	if _, err := writer.Write([]byte(line)); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output.String(), "topsecret") || strings.Contains(output.String(), secret) || strings.Contains(output.String(), "tenant-secret") || strings.Contains(output.String(), "clinical-note") || strings.Contains(output.String(), "admin:password") || strings.Contains(output.String(), "eyJheader") {
		t.Fatalf("structured log leaked sensitive values: %s", output.String())
	}
	var event map[string]interface{}
	if err := json.Unmarshal(output.Bytes(), &event); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"timestamp", "level", "environment", "service", "release", "request_id", "trace_id", "message"} {
		if _, ok := event[field]; !ok {
			t.Fatalf("structured log missing %s: %s", field, output.String())
		}
	}
	if event["request_id"] != "req-safe" || event["trace_id"] != "trace-safe" {
		t.Fatalf("structured log missing request/trace correlation: %#v", event)
	}
}

func TestGatewayEMFContainsSafeCorrelationOnly(t *testing.T) {
	t.Setenv("AUTHCLAW_ENV", "staging")
	t.Setenv("AUTHCLAW_RELEASE", "sha256:abc")
	payload, err := gatewayEMFPayload(time.Unix(1, 0))
	if err != nil {
		t.Fatal(err)
	}
	var event map[string]interface{}
	if err := json.Unmarshal(payload, &event); err != nil {
		t.Fatal(err)
	}
	if event["Environment"] != "staging" || event["Service"] != "gateway" {
		t.Fatalf("missing safe correlation dimensions: %s", payload)
	}
	lower := strings.ToLower(string(payload))
	for _, forbidden := range []string{"authorization", "cookie", "password", "prompt", "document", "tenant_id"} {
		if strings.Contains(lower, forbidden) {
			t.Fatalf("EMF payload contains forbidden field %q: %s", forbidden, payload)
		}
	}
}

func TestAuditLogSummaryExcludesSensitivePayloadFields(t *testing.T) {
	event := &AuditEvent{
		ID: "record-safe", RequestID: "request-safe", TenantID: "tenant-secret",
		DecisionReason: "patient@example.com", CanonicalPayload: "document-secret",
		ExecutionTrace: []string{"prompt-secret"}, Action: "allow", Provider: "openai",
		ResponseStatus: 200, DurationMs: 12,
	}
	summary := auditLogSummary(event)
	for _, forbidden := range []string{"tenant-secret", "patient@example.com", "document-secret", "prompt-secret"} {
		if strings.Contains(summary, forbidden) {
			t.Fatalf("audit log summary leaked %q: %s", forbidden, summary)
		}
	}
	if !strings.Contains(summary, "request_id=request-safe") || !strings.Contains(summary, "response_status=200") {
		t.Fatalf("audit log summary omitted safe operational correlation: %s", summary)
	}
}
