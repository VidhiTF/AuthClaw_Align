package main

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/sqs"
)

type producerSQSSender struct{ calls int }

func (f *producerSQSSender) SendMessage(_ context.Context, _ *sqs.SendMessageInput, _ ...func(*sqs.Options)) (*sqs.SendMessageOutput, error) {
	f.calls++
	return &sqs.SendMessageOutput{}, nil
}

func signedProducerRequest(t *testing.T, secret []byte, now time.Time, tenant string, body []byte) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/v1/audit", bytes.NewReader(body))
	timestamp := strconv.FormatInt(now.Unix(), 10)
	req.Header.Set("X-AuthClaw-Tenant-ID", tenant)
	req.Header.Set("X-AuthClaw-Timestamp", timestamp)
	req.Header.Set("X-AuthClaw-Signature", auditProducerSignature(secret, timestamp, tenant, body))
	return req
}

func TestAuditProducerAuthenticatesAndPublishes(t *testing.T) {
	now := time.Unix(1700000000, 0)
	secret := []byte("test-only-audit-producer-secret-32-bytes")
	sender := &producerSQSSender{}
	stream := &sqsFIFOAuditStream{queueURL: "https://sqs.us-east-1.amazonaws.com/123/audit.fifo", client: sender}
	handler := newAuditProducerHandler(stream, secret, func() time.Time { return now })
	body := []byte(`{"audit_record_id":"550e8400-e29b-41d4-a716-446655440000"}`)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, signedProducerRequest(t, secret, now, "tenant-a", body))
	if recorder.Code != http.StatusNoContent || sender.calls != 1 {
		t.Fatalf("status=%d calls=%d", recorder.Code, sender.calls)
	}
}

func TestAuditProducerRejectsBadSignatureAndStaleRequest(t *testing.T) {
	now := time.Unix(1700000000, 0)
	secret := []byte("test-only-audit-producer-secret-32-bytes")
	sender := &producerSQSSender{}
	handler := newAuditProducerHandler(&sqsFIFOAuditStream{queueURL: "https://sqs.us-east-1.amazonaws.com/123/audit.fifo", client: sender}, secret, func() time.Time { return now })
	body := []byte(`{"audit_record_id":"550e8400-e29b-41d4-a716-446655440000"}`)

	bad := signedProducerRequest(t, secret, now, "tenant-a", body)
	bad.Header.Set("X-AuthClaw-Signature", "00")
	badRecorder := httptest.NewRecorder()
	handler.ServeHTTP(badRecorder, bad)

	stale := signedProducerRequest(t, secret, now, "tenant-a", body)
	stale.Header.Set("X-AuthClaw-Timestamp", "1699999900")
	staleRecorder := httptest.NewRecorder()
	handler.ServeHTTP(staleRecorder, stale)

	if badRecorder.Code != http.StatusUnauthorized || staleRecorder.Code != http.StatusUnauthorized || sender.calls != 0 {
		t.Fatalf("bad=%d stale=%d calls=%d", badRecorder.Code, staleRecorder.Code, sender.calls)
	}
}
