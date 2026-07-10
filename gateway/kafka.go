package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/segmentio/kafka-go"
)

const (
	kafkaGatewayTrafficTopic = "gateway.traffic"
	kafkaAuditDLQTopic       = "audit.deadletter"
)

type kafkaMessageWriter interface {
	WriteMessages(context.Context, ...kafka.Message) error
	Close() error
}

// kafkaWriter is the package-level Kafka writer; nil when Kafka is unavailable.
var kafkaWriter kafkaMessageWriter

// kafkaDLQWriter writes to the audit.deadletter topic for unprocessable messages.
var kafkaDLQWriter kafkaMessageWriter

var kafkaPublishFailures atomic.Uint64
var kafkaDLQPublished atomic.Uint64
var kafkaDLQPublishFailures atomic.Uint64

// InitKafkaProducer configures the Kafka writers using KAFKA_BROKERS env var.
// If the variable is unset, producers are left nil and events fall back to stdout.
func InitKafkaProducer() {
	brokers := os.Getenv("KAFKA_BROKERS")
	if strings.TrimSpace(brokers) == "" {
		log.Println("Kafka producers disabled; audit events will use local fallbacks")
		return
	}

	brokerList := strings.Split(brokers, ",")

	kafkaWriter = &kafka.Writer{
		Addr:                   kafka.TCP(brokerList...),
		Topic:                  kafkaGatewayTrafficTopic,
		Balancer:               &kafka.Hash{},
		BatchTimeout:           10 * time.Millisecond,
		Async:                  true,
		AllowAutoTopicCreation: false,
		Completion: func(_ []kafka.Message, err error) {
			if err != nil {
				kafkaPublishFailures.Add(1)
				log.Printf("[KAFKA] Failed to publish audit event asynchronously: %v", err)
			}
		},
	}

	kafkaDLQWriter = &kafka.Writer{
		Addr:                   kafka.TCP(brokerList...),
		Topic:                  kafkaAuditDLQTopic,
		Balancer:               &kafka.Hash{},
		BatchTimeout:           10 * time.Millisecond,
		Async:                  true,
		AllowAutoTopicCreation: false,
		Completion: func(messages []kafka.Message, err error) {
			if err != nil {
				kafkaDLQPublishFailures.Add(1)
				log.Printf("[DLQ] Failed to publish to %s asynchronously: %v", kafkaAuditDLQTopic, err)
				return
			}
			kafkaDLQPublished.Add(uint64(len(messages)))
		},
	}

	log.Printf("Kafka producers initialised (brokers: %s, topics: %s, %s)", brokers, kafkaGatewayTrafficTopic, kafkaAuditDLQTopic)
}

func auditEventKafkaMessage(event *AuditEvent, payload []byte) kafka.Message {
	return kafka.Message{
		Key:   []byte(event.TenantID),
		Value: payload,
		Headers: []kafka.Header{
			{Key: "event_id", Value: []byte(event.ID)},
			{Key: "tenant_id", Value: []byte(event.TenantID)},
			{Key: "request_id", Value: []byte(event.RequestID)},
		},
	}
}

// PublishAuditEvent serialises the event to JSON and writes it asynchronously to Kafka.
// Returns an error if serialisation fails; Kafka write errors are logged and swallowed.
func PublishAuditEvent(event *AuditEvent) error {
	if kafkaWriter == nil {
		return nil // Kafka not configured — caller falls back to stdout
	}

	payload, err := json.Marshal(event)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err = kafkaWriter.WriteMessages(ctx, auditEventKafkaMessage(event, payload))
	if err != nil {
		// Non-fatal: log and continue so request path is not affected.
		kafkaPublishFailures.Add(1)
		log.Printf("[KAFKA] Failed to publish audit event: %v", err)
	}

	return nil
}

func dlqKafkaMessage(dlq DLQMessage, envelope []byte) kafka.Message {
	return kafka.Message{
		Key:   []byte(dlq.TenantID),
		Value: envelope,
		Headers: []kafka.Header{
			{Key: "tenant_id", Value: []byte(dlq.TenantID)},
			{Key: "request_id", Value: []byte(dlq.RequestID)},
		},
	}
}

// DLQMessage is the envelope written to audit.deadletter on consumer failure.
type DLQMessage struct {
	OriginalPayload json.RawMessage `json:"original_payload"`
	ErrorReason     string          `json:"error_reason"`
	FailedAt        time.Time       `json:"failed_at"`
	TenantID        string          `json:"tenant_id,omitempty"`
	RequestID       string          `json:"request_id,omitempty"`
}

// PublishToDLQ writes a failed message envelope to the audit.deadletter topic.
// It is non-blocking: write errors are only logged.
func PublishToDLQ(originalPayload []byte, errorReason, tenantID, requestID string) {
	if kafkaDLQWriter == nil {
		log.Printf("[DLQ] Writer not initialised — dropping failed message (reason: %s)", errorReason)
		return
	}

	dlq := DLQMessage{
		OriginalPayload: json.RawMessage(originalPayload),
		ErrorReason:     errorReason,
		FailedAt:        time.Now().UTC(),
		TenantID:        tenantID,
		RequestID:       requestID,
	}

	envelope, err := json.Marshal(dlq)
	if err != nil {
		log.Printf("[DLQ] Failed to marshal DLQ envelope: %v", err)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := kafkaDLQWriter.WriteMessages(ctx, dlqKafkaMessage(dlq, envelope)); err != nil {
		kafkaDLQPublishFailures.Add(1)
		log.Printf("[DLQ] Failed to publish to audit.deadletter: %v", err)
	} else {
		kafkaDLQPublished.Add(1)
		log.Printf("[DLQ] Published failed event to audit.deadletter (tenant=%s reason=%s)", tenantID, errorReason)
	}
}

// CloseKafkaProducer gracefully flushes and closes both Kafka writers on shutdown.
func CloseKafkaProducer() {
	for _, w := range []kafkaMessageWriter{kafkaWriter, kafkaDLQWriter} {
		if w != nil {
			if err := w.Close(); err != nil {
				log.Printf("[KAFKA] Error closing writer: %v", err)
			}
		}
	}
}

func KafkaMetricsSnapshot() map[string]uint64 {
	return map[string]uint64{
		"authclaw_gateway_kafka_publish_failures_total":     kafkaPublishFailures.Load(),
		"authclaw_gateway_kafka_dlq_published_total":        kafkaDLQPublished.Load(),
		"authclaw_gateway_kafka_dlq_publish_failures_total": kafkaDLQPublishFailures.Load(),
	}
}

func KafkaMetricsHandler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	for name, value := range KafkaMetricsSnapshot() {
		fmt.Fprintf(w, "# TYPE %s counter\n%s %d\n", name, name, value)
	}
	for name, value := range AuditMetricsSnapshot() {
		fmt.Fprintf(w, "# TYPE %s counter\n%s %d\n", name, name, value)
	}
	for name, value := range RedactionMetricsSnapshot() {
		fmt.Fprintf(w, "# TYPE %s counter\n%s %d\n", name, name, value)
	}
}
