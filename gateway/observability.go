package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"regexp"
	"strings"
	"time"
)

var sensitiveLogValue = regexp.MustCompile(`(?i)(authorization|cookie|set-cookie|api[_-]?key|access[_-]?token|token|secret|password|credential|prompt|messages?|document|content|tenant(?:_id)?)=([^\s,]+)`)
var bearerLogValue = regexp.MustCompile(`(?i)bearer\s+[a-z0-9._~+/=-]+`)
var jwtLogValue = regexp.MustCompile(`\beyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\b`)
var credentialURLLogValue = regexp.MustCompile(`(?i)(https?://)[^/@\s:]+(?::[^/@\s]*)?@`)
var emailLogValue = regexp.MustCompile(`(?i)\b[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}\b`)
var requestIDLogValue = regexp.MustCompile(`\brequest_id=([a-zA-Z0-9._:-]{1,128})\b`)
var traceIDLogValue = regexp.MustCompile(`\btrace_id=([a-zA-Z0-9._:-]{1,128})\b`)

type safeJSONLogWriter struct {
	destination io.Writer
}

func sanitizeLogMessage(message string) string {
	message = sensitiveLogValue.ReplaceAllString(message, "$1=[REDACTED]")
	message = bearerLogValue.ReplaceAllString(message, "Bearer [REDACTED]")
	message = jwtLogValue.ReplaceAllString(message, "[REDACTED_JWT]")
	message = credentialURLLogValue.ReplaceAllString(message, "$1[REDACTED]@")
	return emailLogValue.ReplaceAllString(message, "[REDACTED_EMAIL]")
}

func (writer safeJSONLogWriter) Write(payload []byte) (int, error) {
	message := sanitizeLogMessage(strings.TrimSpace(string(payload)))
	requestID := ""
	if match := requestIDLogValue.FindStringSubmatch(message); len(match) == 2 {
		requestID = match[1]
	}
	traceID := ""
	if match := traceIDLogValue.FindStringSubmatch(message); len(match) == 2 {
		traceID = match[1]
	}
	level := "info"
	lower := strings.ToLower(message)
	if strings.Contains(lower, "error") || strings.Contains(lower, "failed") || strings.Contains(lower, "fatal") {
		level = "error"
	}
	event := map[string]interface{}{
		"timestamp":   time.Now().UTC().Format(time.RFC3339Nano),
		"level":       level,
		"environment": os.Getenv("AUTHCLAW_ENV"),
		"service":     "gateway",
		"release":     os.Getenv("AUTHCLAW_RELEASE"),
		"request_id":  requestID,
		"trace_id":    traceID,
		"message":     message,
	}
	encoded, err := json.Marshal(event)
	if err != nil {
		return 0, err
	}
	encoded = append(encoded, '\n')
	if _, err := writer.destination.Write(encoded); err != nil {
		return 0, err
	}
	return len(payload), nil
}

func configureStructuredLogging() {
	log.SetFlags(0)
	log.SetOutput(safeJSONLogWriter{destination: os.Stdout})
}

type cloudWatchMetricDefinition struct {
	Name string
	Unit string
}

type cloudWatchMetricDirective struct {
	Namespace  string
	Dimensions [][]string
	Metrics    []cloudWatchMetricDefinition
}

func gatewayEMFPayload(now time.Time) ([]byte, error) {
	values := AuditMetricsSnapshot()
	definitions := make([]cloudWatchMetricDefinition, 0, len(values))
	event := map[string]interface{}{
		"Environment": os.Getenv("AUTHCLAW_ENV"),
		"Service":     "gateway",
		"Release":     os.Getenv("AUTHCLAW_RELEASE"),
	}
	for name, value := range values {
		definitions = append(definitions, cloudWatchMetricDefinition{Name: name, Unit: "Count"})
		event[name] = value
	}
	event["_aws"] = map[string]interface{}{
		"Timestamp": now.UnixMilli(),
		"CloudWatchMetrics": []cloudWatchMetricDirective{{
			Namespace:  "AuthClaw/Gateway",
			Dimensions: [][]string{{"Environment", "Service", "Release"}},
			Metrics:    definitions,
		}},
	}
	return json.Marshal(event)
}

func startGatewayEMF(stop <-chan struct{}) {
	interval := boundedDuration("GATEWAY_EMF_INTERVAL_SECONDS", 60, 10, 300)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case now := <-ticker.C:
			payload, err := gatewayEMFPayload(now)
			if err == nil {
				// Keep the event as raw JSON so CloudWatch Logs can extract EMF.
				fmt.Println(string(payload))
			}
		}
	}
}
