package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	"os"
	"path"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
)

const sqsMaxMessageBytes = 1_048_576

type sqsSender interface {
	SendMessage(context.Context, *sqs.SendMessageInput, ...func(*sqs.Options)) (*sqs.SendMessageOutput, error)
}

type sqsFIFOAuditStream struct {
	queueURL string
	client   sqsSender
}

func sqsQueueRegion(host string) string {
	labels := strings.Split(strings.ToLower(host), ".")
	for i, label := range labels {
		if (label == "sqs" || strings.HasPrefix(label, "sqs-")) && i+1 < len(labels) {
			return labels[i+1]
		}
	}
	return ""
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
	queueRegion := sqsQueueRegion(host)
	awsHost := strings.HasSuffix(host, ".amazonaws.com") || strings.HasSuffix(host, ".amazonaws.com.cn")
	if !awsHost || queueRegion == "" {
		return nil, fmt.Errorf("SQS_AUDIT_QUEUE_URL must use a regional AWS SQS endpoint")
	}
	cfg, err := config.LoadDefaultConfig(context.Background())
	if err != nil {
		return nil, fmt.Errorf("load AWS SDK configuration: %w", err)
	}
	if cfg.Region != "" && !strings.EqualFold(cfg.Region, queueRegion) {
		return nil, fmt.Errorf("SQS queue region %q does not match AWS SDK region %q", queueRegion, cfg.Region)
	}
	cfg.Region = queueRegion
	return &sqsFIFOAuditStream{queueURL: queueURL, client: sqs.NewFromConfig(cfg)}, nil
}

func (s *sqsFIFOAuditStream) Enabled() bool { return true }

func canonicalAuditRecordID(value string) (string, error) {
	compact := strings.ReplaceAll(strings.TrimSpace(value), "-", "")
	if len(value) != 36 || len(compact) != 32 || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' {
		return "", fmt.Errorf("SQS FIFO audit_record_id must be a canonical UUID")
	}
	if _, err := hex.DecodeString(compact); err != nil {
		return "", fmt.Errorf("SQS FIFO audit_record_id must be a canonical UUID")
	}
	return strings.ToLower(value), nil
}

func (s *sqsFIFOAuditStream) send(ctx context.Context, tenantID, recordID string, payload []byte) error {
	if strings.TrimSpace(tenantID) == "" || strings.TrimSpace(recordID) == "" {
		return fmt.Errorf("SQS FIFO audit publish requires tenant_id and audit_record_id")
	}
	canonicalID, err := canonicalAuditRecordID(recordID)
	if err != nil {
		return err
	}
	if len(tenantID) > 128 {
		return fmt.Errorf("SQS FIFO tenant_id must not exceed 128 characters")
	}
	if len(payload) > sqsMaxMessageBytes {
		return fmt.Errorf("SQS audit message exceeds %d-byte limit", sqsMaxMessageBytes)
	}
	_, err = s.client.SendMessage(ctx, &sqs.SendMessageInput{
		QueueUrl:               aws.String(s.queueURL),
		MessageBody:            aws.String(string(payload)),
		MessageGroupId:         aws.String(tenantID),
		MessageDeduplicationId: aws.String(canonicalID),
	})
	return err
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
