package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

const auditProducerClockSkew = 30 * time.Second

type auditProducerClient struct {
	url    string
	secret []byte
	client *http.Client
	now    func() time.Time
}

func auditProducerSecret() ([]byte, error) {
	secret := []byte(os.Getenv("AUDIT_PRODUCER_SECRET"))
	if len(secret) < 32 {
		return nil, fmt.Errorf("AUDIT_PRODUCER_SECRET must contain at least 32 bytes")
	}
	return secret, nil
}

func auditProducerSignature(secret []byte, timestamp, tenantID string, payload []byte) string {
	digest := sha256.Sum256(payload)
	mac := hmac.New(sha256.New, secret)
	_, _ = io.WriteString(mac, timestamp+"\n"+tenantID+"\n"+hex.EncodeToString(digest[:]))
	return hex.EncodeToString(mac.Sum(nil))
}

func newAuditProducerClient() (*auditProducerClient, error) {
	rawURL := strings.TrimSpace(os.Getenv("AUDIT_PRODUCER_URL"))
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.Path != "/v1/audit" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, fmt.Errorf("AUDIT_PRODUCER_URL must be an absolute HTTPS /v1/audit URL")
	}
	secret, err := auditProducerSecret()
	if err != nil {
		return nil, err
	}
	return &auditProducerClient{
		url: rawURL, secret: secret,
		client: &http.Client{Timeout: 5 * time.Second}, now: time.Now,
	}, nil
}

func (c *auditProducerClient) Enabled() bool { return true }

func (c *auditProducerClient) publish(ctx context.Context, tenantID string, payload []byte) error {
	if strings.TrimSpace(tenantID) == "" || len(tenantID) > 128 {
		return fmt.Errorf("audit producer requires a tenant_id of at most 128 characters")
	}
	if len(payload) > sqsMaxMessageBytes {
		return fmt.Errorf("audit producer payload exceeds %d-byte limit", sqsMaxMessageBytes)
	}
	timestamp := strconv.FormatInt(c.now().Unix(), 10)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-AuthClaw-Tenant-ID", tenantID)
	req.Header.Set("X-AuthClaw-Timestamp", timestamp)
	req.Header.Set("X-AuthClaw-Signature", auditProducerSignature(c.secret, timestamp, tenantID, payload))
	response, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		return fmt.Errorf("audit producer returned HTTP %d", response.StatusCode)
	}
	return nil
}

func (c *auditProducerClient) PublishEvent(event *AuditEvent) error {
	payload, err := json.Marshal(event)
	if err != nil {
		return err
	}
	return c.publish(context.Background(), event.TenantID, payload)
}

func (c *auditProducerClient) PublishOutboxPayload(tenantID string, payload []byte) error {
	return c.publishOutboxPayloadContext(context.Background(), tenantID, payload)
}

func (c *auditProducerClient) publishOutboxPayloadContext(ctx context.Context, tenantID string, payload []byte) error {
	return c.publish(ctx, tenantID, payload)
}

func (c *auditProducerClient) PublishDLQ(_ []byte, reason, tenantID, _ string) {
	log.Printf("[DLQ] producer request retained for normal SQS redrive (tenant=%s reason=%s)", tenantID, reason)
}

func (c *auditProducerClient) Close() { c.client.CloseIdleConnections() }

func newAuditProducerHandler(stream *sqsFIFOAuditStream, secret []byte, now func() time.Time) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", HealthHandler)
	mux.HandleFunc("POST /v1/audit", func(w http.ResponseWriter, r *http.Request) {
		tenantID := strings.TrimSpace(r.Header.Get("X-AuthClaw-Tenant-ID"))
		timestamp := r.Header.Get("X-AuthClaw-Timestamp")
		unixTime, err := strconv.ParseInt(timestamp, 10, 64)
		if err != nil || tenantID == "" || len(tenantID) > 128 || absDuration(now().Sub(time.Unix(unixTime, 0))) > auditProducerClockSkew {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, sqsMaxMessageBytes+1))
		if err != nil || len(body) > sqsMaxMessageBytes {
			http.Error(w, "invalid payload", http.StatusRequestEntityTooLarge)
			return
		}
		expected, err := hex.DecodeString(auditProducerSignature(secret, timestamp, tenantID, body))
		provided, providedErr := hex.DecodeString(r.Header.Get("X-AuthClaw-Signature"))
		if err != nil || providedErr != nil || len(provided) != len(expected) || subtle.ConstantTimeCompare(provided, expected) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if err := stream.PublishOutboxPayload(tenantID, body); err != nil {
			http.Error(w, "publish failed", http.StatusBadGateway)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	return mux
}

func absDuration(value time.Duration) time.Duration {
	if value < 0 {
		return -value
	}
	return value
}

func runAuditProducerServer(server *http.Server, stream interface{ Close() }, signals <-chan os.Signal, serve func() error) (err error) {
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		err = errors.Join(err, shutdownHTTPServer(ctx, server))
		stream.Close()
	}()
	return serveUntilSignal(serve, signals, "AuthClaw audit producer")
}

func runAuditProducer() error {
	secret, err := auditProducerSecret()
	if err != nil {
		return err
	}
	stream, err := newSQSFIFOAuditStream()
	if err != nil {
		return err
	}
	server := &http.Server{
		Addr:              ":8090",
		Handler:           newAuditProducerHandler(stream, secret, time.Now),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
	}
	signals, stopSignals := terminationSignals()
	defer stopSignals()
	return runAuditProducerServer(server, stream, signals, server.ListenAndServe)
}
