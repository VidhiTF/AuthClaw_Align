package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
	"time"
)

type sqsFIFOAuditStream struct {
	queueURL string
	client   *http.Client
}

func newSQSFIFOAuditStream() (*sqsFIFOAuditStream, error) {
	queueURL := strings.TrimSpace(os.Getenv("SQS_AUDIT_QUEUE_URL"))
	parsed, err := url.Parse(queueURL)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, fmt.Errorf("SQS_AUDIT_QUEUE_URL must be an absolute HTTPS FIFO queue URL")
	}
	if !strings.HasSuffix(path.Base(parsed.Path), ".fifo") {
		return nil, fmt.Errorf("SQS_AUDIT_QUEUE_URL must identify a .fifo queue")
	}
	host := strings.ToLower(parsed.Hostname())
	awsHost := strings.HasSuffix(host, ".amazonaws.com") || strings.HasSuffix(host, ".amazonaws.com.cn")
	if !awsHost || (!strings.Contains(host, ".sqs.") && !strings.HasPrefix(host, "sqs.")) {
		return nil, fmt.Errorf("SQS_AUDIT_QUEUE_URL must use an AWS SQS endpoint")
	}
	return &sqsFIFOAuditStream{
		queueURL: queueURL,
		client:   &http.Client{Timeout: 5 * time.Second},
	}, nil
}

func (s *sqsFIFOAuditStream) Enabled() bool { return true }

func (s *sqsFIFOAuditStream) send(ctx context.Context, tenantID, recordID string, payload []byte) error {
	if strings.TrimSpace(tenantID) == "" || strings.TrimSpace(recordID) == "" {
		return fmt.Errorf("SQS FIFO audit publish requires tenant_id and audit_record_id")
	}
	if len(tenantID) > 128 || len(recordID) > 128 {
		return fmt.Errorf("SQS FIFO tenant_id and audit_record_id must not exceed 128 characters")
	}
	form := url.Values{
		"Action":                 {"SendMessage"},
		"Version":                {"2012-11-05"},
		"MessageBody":            {string(payload)},
		"MessageGroupId":         {tenantID},
		"MessageDeduplicationId": {recordID},
	}
	body := []byte(form.Encode())
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.queueURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if err := SignAWSRequest(req, body, "sqs"); err != nil {
		return err
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		responseBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("SQS SendMessage failed: status=%d body=%s", resp.StatusCode, strings.TrimSpace(string(responseBody)))
	}
	return nil
}

func (s *sqsFIFOAuditStream) PublishEvent(event *AuditEvent) error {
	payload, err := json.Marshal(event)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return s.send(ctx, event.TenantID, event.ID, payload)
}

func (s *sqsFIFOAuditStream) PublishOutboxPayload(tenantID string, payload []byte) error {
	var identity struct {
		ID            string `json:"id"`
		RecordID      string `json:"record_id"`
		AuditRecordID string `json:"audit_record_id"`
	}
	if err := json.Unmarshal(payload, &identity); err != nil {
		return err
	}
	recordID := identity.AuditRecordID
	if recordID == "" {
		recordID = identity.RecordID
	}
	if recordID == "" {
		recordID = identity.ID
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return s.send(ctx, tenantID, recordID, payload)
}

func (s *sqsFIFOAuditStream) PublishDLQ(_ []byte, reason, tenantID, _ string) {
	log.Printf("[DLQ] SQS consumer/DLQ is not implemented; retaining existing local evidence (tenant=%s reason=%s)", tenantID, reason)
}

func (s *sqsFIFOAuditStream) Close() {}
