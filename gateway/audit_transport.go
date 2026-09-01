package main

import (
	"fmt"
	"os"
	"strings"
)

const (
	defaultAuditEventsTopic = "audit.events"
	defaultAuditDLQTopic    = "audit.deadletter"
)

type auditTopics struct {
	events string
	dlq    string
}

type auditStream interface {
	Enabled() bool
	PublishEvent(*AuditEvent) error
	PublishOutboxPayload(string, []byte) error
	PublishDLQ([]byte, string, string, string)
	Close()
}

var activeAuditStream auditStream = &kafkaAuditStream{
	topics: auditTopics{events: defaultAuditEventsTopic, dlq: defaultAuditDLQTopic},
}

func auditTopic(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}

func InitAuditTransport() error {
	transport := strings.ToLower(strings.TrimSpace(os.Getenv("AUDIT_STREAM_TRANSPORT")))
	if transport == "" {
		transport = "kafka"
	}
	if transport == "sqs_fifo" {
		adapter, err := newSQSFIFOAuditStream()
		if err != nil {
			return err
		}
		activeAuditStream = adapter
		return nil
	}
	if transport != "kafka" {
		return fmt.Errorf("unsupported AUDIT_STREAM_TRANSPORT %q; supported values: kafka, sqs_fifo", transport)
	}
	adapter := &kafkaAuditStream{topics: auditTopics{
		events: auditTopic("KAFKA_AUDIT_TOPIC", defaultAuditEventsTopic),
		dlq:    auditTopic("KAFKA_DLQ_TOPIC", defaultAuditDLQTopic),
	}}
	adapter.Init()
	activeAuditStream = adapter
	return nil
}

func AuditTransportEnabled() bool { return activeAuditStream.Enabled() }

func PublishAuditEvent(event *AuditEvent) error { return activeAuditStream.PublishEvent(event) }

func PublishAuditOutboxPayload(tenantID string, payload []byte) error {
	return activeAuditStream.PublishOutboxPayload(tenantID, payload)
}

func PublishToDLQ(payload []byte, reason, tenantID, requestID string) {
	activeAuditStream.PublishDLQ(payload, reason, tenantID, requestID)
}

func CloseAuditTransport() { activeAuditStream.Close() }
