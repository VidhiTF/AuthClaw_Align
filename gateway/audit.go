package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lib/pq"
)

// AuditEvent represents the schema of traffic events logged by the gateway.
type AuditEvent struct {
	ID                 string    `json:"id"`
	RequestID          string    `json:"request_id"`
	Timestamp          time.Time `json:"timestamp"`
	TenantID           string    `json:"tenant_id"`
	PolicyID           string    `json:"policy_id"`
	Action             string    `json:"action"`
	DecisionReason     string    `json:"reason"`
	Provider           string    `json:"provider"`
	Model              string    `json:"model"`
	PromptCount        int       `json:"prompt_count"`
	RequestSize        int       `json:"request_size"`
	ResponseStatus     int       `json:"response_status"`
	DurationMs         int64     `json:"duration_ms"`
	FrameworksAffected []string  `json:"frameworks_affected,omitempty"`
	ExecutionTrace     []string  `json:"execution_trace,omitempty"`
	IdempotencyKey     string    `json:"idempotency_key,omitempty"`
	TenantSequence     int64     `json:"tenant_sequence,omitempty"`
	ChainVersion       int       `json:"chain_version,omitempty"`
	CanonicalPayload   string    `json:"canonical_payload,omitempty"`
	PriorHash          string    `json:"prior_hash,omitempty"`
	IntegrityHash      string    `json:"integrity_hash,omitempty"`
}

var (
	auditPostgresFailures       atomic.Uint64
	auditOutboxWrites           atomic.Uint64
	auditOutboxFailures         atomic.Uint64
	auditFailClosedFailures     atomic.Uint64
	auditIdempotencyCollisions  atomic.Uint64
	auditOutboxBacklog          atomic.Uint64
	auditOutboxOldestAge        atomic.Uint64
	auditRecoveryReplayFailures atomic.Uint64
	auditRecoveryScanFailures   atomic.Uint64
	auditFailOpenLosses         atomic.Uint64
	auditPostResponseFailures   atomic.Uint64
)

var (
	auditEventEmitter    = EmitAuditEvent
	auditRecoveryPersist = persistAuditMetadata
	auditRecoveryPublish = publishPendingAuditOutbox
	auditOutboxWrite     = func(file *os.File, payload []byte) (int, error) { return file.Write(payload) }
	auditOutboxSyncDir   = syncAuditDirectory
)

type auditOutboxEnvelope struct {
	FailedAt    time.Time   `json:"failed_at"`
	ErrorReason string      `json:"error_reason"`
	Event       *AuditEvent `json:"event"`
}

type auditPersistenceError struct {
	cause             error
	recoveryAvailable bool
}

type auditOutboxIndeterminateError struct{ cause error }

func (e *auditOutboxIndeterminateError) Error() string { return e.cause.Error() }
func (e *auditOutboxIndeterminateError) Unwrap() error { return e.cause }

const auditRecoveryReplayLimit = 100

func (e *auditPersistenceError) Error() string { return e.cause.Error() }
func (e *auditPersistenceError) Unwrap() error { return e.cause }

func auditFailClosedEnabled() bool {
	return envBool("AUDIT_FAIL_CLOSED", isProductionEnv())
}

func auditOutboxPath() string {
	if path := strings.TrimSpace(os.Getenv("AUDIT_OUTBOX_PATH")); path != "" {
		return path
	}
	return filepath.Join(os.TempDir(), "authclaw", "audit-outbox.ndjson")
}

func writeAuditOutbox(event *AuditEvent, reason error) error {
	return writeAuditOutboxBatch([]*AuditEvent{event}, reason)
}

func writeAuditOutboxBatch(events []*AuditEvent, reason error) error {
	return writeAuditOutboxBatchAt(events, reason, time.Now().UTC())
}

func writeAuditOutboxBatchAt(events []*AuditEvent, reason error, failedAt time.Time) error {
	if len(events) == 0 {
		return fmt.Errorf("audit recovery batch is empty")
	}
	payload := make([]byte, 0, len(events)*512)
	reasonText := "unknown"
	if reason != nil {
		reasonText = reason.Error()
	}
	tenantID := ""
	for _, event := range events {
		if event == nil {
			return fmt.Errorf("audit event is nil")
		}
		if tenantID == "" {
			tenantID = event.TenantID
		} else if event.TenantID != tenantID {
			return fmt.Errorf("audit recovery batch spans multiple tenants")
		}
		line, err := json.Marshal(auditOutboxEnvelope{FailedAt: failedAt, ErrorReason: reasonText, Event: event})
		if err != nil {
			return err
		}
		payload = append(payload, line...)
		payload = append(payload, '\n')
	}
	if err := writeAuditRecoveryPayload(payload, tenantID, failedAt); err != nil {
		return err
	}
	auditOutboxWrites.Add(uint64(len(events)))
	return nil
}

func writeAuditRecoveryPayload(payload []byte, tenantID string, failedAt time.Time) error {
	path := auditOutboxPath()
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	file, err := os.CreateTemp(dir, ".audit-recovery-*.tmp")
	if err != nil {
		return err
	}
	tempPath := file.Name()
	defer os.Remove(tempPath)
	written, err := auditOutboxWrite(file, payload)
	if err == nil && written != len(payload) {
		err = io.ErrShortWrite
	}
	if err != nil {
		return errors.Join(err, file.Close())
	}
	if err := file.Sync(); err != nil {
		return errors.Join(err, file.Close())
	}
	if err := file.Close(); err != nil {
		return err
	}
	readyPath := auditRecoveryReadyPath(path, payload, tenantID, failedAt)
	if err := os.Rename(tempPath, readyPath); err != nil {
		if _, statErr := os.Stat(readyPath); statErr != nil {
			return err
		}
	}
	if err := auditOutboxSyncDir(dir); err != nil {
		return &auditOutboxIndeterminateError{cause: err}
	}
	return nil
}

func auditRecoveryReadyPath(path string, payload []byte, tenantID string, failedAt time.Time) string {
	tenantHash, payloadHash := sha256.Sum256([]byte(tenantID)), sha256.Sum256(payload)
	return fmt.Sprintf("%s.%020d.%x.%x.ready", path, failedAt.UnixNano(), tenantHash, payloadHash)
}

func syncAuditDirectory(path string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	return errors.Join(directory.Sync(), directory.Close())
}

func removeAuditRecovery(path string) error {
	var err error
	for range 100 {
		if err = os.Remove(path); err == nil || os.IsNotExist(err) {
			return nil
		}
		time.Sleep(5 * time.Millisecond)
	}
	return err
}

func statAuditRecovery(path string) (os.FileInfo, error) {
	var info os.FileInfo
	var err error
	for range 100 {
		if info, err = os.Stat(path); err == nil || os.IsNotExist(err) {
			return info, err
		}
		time.Sleep(5 * time.Millisecond)
	}
	return nil, err
}

func decodeAuditRecovery(reader io.Reader) ([]auditOutboxEnvelope, error) {
	decoder := json.NewDecoder(reader)
	var envelopes []auditOutboxEnvelope
	for {
		var envelope auditOutboxEnvelope
		if err := decoder.Decode(&envelope); errors.Is(err, io.EOF) {
			return envelopes, nil
		} else if err != nil {
			return nil, err
		}
		if envelope.Event == nil {
			return nil, fmt.Errorf("audit recovery record has no event")
		}
		envelopes = append(envelopes, envelope)
	}
}

func recoverAuditTemps(path string) error {
	dir := filepath.Dir(path)
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasPrefix(entry.Name(), ".audit-recovery-") || !strings.HasSuffix(entry.Name(), ".tmp") {
			continue
		}
		info, err := entry.Info()
		if err != nil || time.Since(info.ModTime()) < time.Minute {
			continue
		}
		tempPath := filepath.Join(dir, entry.Name())
		payload, readErr := os.ReadFile(tempPath)
		if os.IsNotExist(readErr) {
			continue
		}
		if readErr != nil {
			return readErr
		}
		envelopes, decodeErr := decodeAuditRecovery(bytes.NewReader(payload))
		failedAt, tenantID := info.ModTime(), ""
		if decodeErr == nil && len(envelopes) > 0 {
			tenantID = envelopes[0].Event.TenantID
			for _, envelope := range envelopes {
				if envelope.Event.TenantID != tenantID {
					decodeErr = fmt.Errorf("audit recovery batch spans multiple tenants")
					break
				}
				if !envelope.FailedAt.IsZero() && envelope.FailedAt.Before(failedAt) {
					failedAt = envelope.FailedAt
				}
			}
		}
		readyPath := auditRecoveryReadyPath(path, payload, tenantID, failedAt)
		if decodeErr != nil || len(envelopes) == 0 {
			readyPath = fmt.Sprintf("%s.%020d.invalid.%x.ready", path, failedAt.UnixNano(), sha256.Sum256(payload))
		}
		if err := os.Rename(tempPath, readyPath); err != nil {
			if _, statErr := os.Stat(readyPath); statErr != nil {
				return err
			}
		}
		if err := auditOutboxSyncDir(dir); err != nil {
			return &auditOutboxIndeterminateError{cause: err}
		}
	}
	return nil
}

func auditRecoveryFiles() ([]string, error) {
	path := auditOutboxPath()
	if err := recoverAuditTemps(path); err != nil {
		return nil, err
	}
	if legacyPath, err := claimLegacyAuditRecovery(path); err != nil {
		return nil, err
	} else if legacyPath != "" {
		if err := migrateLegacyAuditRecovery(legacyPath); err != nil {
			return nil, err
		}
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	prefix := filepath.Base(path) + "."
	files := make([]string, 0)
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasPrefix(entry.Name(), prefix) && strings.HasSuffix(entry.Name(), ".ready") && !strings.HasSuffix(entry.Name(), ".legacy.ready") {
			files = append(files, filepath.Join(filepath.Dir(path), entry.Name()))
		}
	}
	return files, nil
}

func claimLegacyAuditRecovery(path string) (string, error) {
	legacyPath := path + ".legacy.ready"
	if _, err := statAuditRecovery(legacyPath); err == nil {
		return legacyPath, nil
	} else if !os.IsNotExist(err) {
		return "", err
	}
	if info, err := statAuditRecovery(path); err != nil || info.IsDir() {
		if os.IsNotExist(err) || err == nil {
			return "", nil
		}
		return "", err
	}
	if err := os.Link(path, legacyPath); err != nil {
		if _, statErr := os.Stat(legacyPath); statErr == nil {
			return legacyPath, nil
		} else if os.IsNotExist(statErr) {
			if _, sourceErr := os.Stat(path); os.IsNotExist(sourceErr) {
				return "", nil
			}
		}
		return "", err
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return "", err
	}
	if err := auditOutboxSyncDir(filepath.Dir(path)); err != nil {
		return "", &auditOutboxIndeterminateError{cause: err}
	}
	return legacyPath, nil
}

func migrateLegacyAuditRecovery(path string) error {
	info, statErr := statAuditRecovery(path)
	if os.IsNotExist(statErr) {
		return nil
	}
	if statErr != nil {
		return statErr
	}
	var envelopes []auditOutboxEnvelope
	var err error
	for range 100 {
		envelopes, err = readAuditRecovery(path)
		var pathErr *os.PathError
		if err == nil || os.IsNotExist(err) || !errors.As(err, &pathErr) {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		payload, readErr := os.ReadFile(path)
		if readErr != nil {
			if os.IsNotExist(readErr) {
				return nil
			}
			return readErr
		}
		invalid := fmt.Sprintf("%s.%020d.invalid.%x.ready", strings.TrimSuffix(path, ".legacy.ready"), info.ModTime().UnixNano(), sha256.Sum256(payload))
		if renameErr := os.Rename(path, invalid); renameErr != nil {
			if _, statErr := os.Stat(invalid); statErr != nil {
				return renameErr
			}
		}
		return auditOutboxSyncDir(filepath.Dir(path))
	}
	type group struct {
		events   []*AuditEvent
		failedAt time.Time
	}
	groups := make(map[string]*group)
	for _, envelope := range envelopes {
		if envelope.FailedAt.IsZero() {
			envelope.FailedAt = info.ModTime()
		}
		batch := groups[envelope.Event.TenantID]
		if batch == nil {
			batch = &group{failedAt: envelope.FailedAt}
			groups[envelope.Event.TenantID] = batch
		}
		batch.events = append(batch.events, envelope.Event)
		if envelope.FailedAt.Before(batch.failedAt) {
			batch.failedAt = envelope.FailedAt
		}
	}
	for _, batch := range groups {
		for start := 0; start < len(batch.events); start += auditRecoveryReplayLimit {
			end := min(start+auditRecoveryReplayLimit, len(batch.events))
			if err := writeAuditOutboxBatchAt(batch.events[start:end], errors.New("legacy audit recovery"), batch.failedAt.Add(time.Duration(start))); err != nil {
				return err
			}
		}
	}
	if err := removeAuditRecovery(path); err != nil {
		return err
	}
	return auditOutboxSyncDir(filepath.Dir(path))
}

func readAuditRecovery(path string) ([]auditOutboxEnvelope, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return decodeAuditRecovery(file)
}

func checkpointAuditRecovery(path string, envelopes []auditOutboxEnvelope) error {
	payload := make([]byte, 0, len(envelopes)*512)
	for _, envelope := range envelopes {
		line, err := json.Marshal(envelope)
		if err != nil {
			return err
		}
		payload = append(payload, append(line, '\n')...)
	}
	if err := writeAuditRecoveryPayload(payload, envelopes[0].Event.TenantID, envelopes[0].FailedAt); err != nil {
		return err
	}
	if err := removeAuditRecovery(path); err != nil {
		return err
	}
	return auditOutboxSyncDir(filepath.Dir(path))
}

func replayAuditRecovery(ctx context.Context, tenantID string, persist func(context.Context, *AuditEvent) error) (bool, bool) {
	files, err := auditRecoveryFiles()
	if err != nil {
		auditRecoveryReplayFailures.Add(1)
		log.Printf("[AUDIT] recovery scan failed: %v", err)
		return false, false
	}
	replayed := 0
	tenantMarker := fmt.Sprintf(".%x.", sha256.Sum256([]byte(tenantID)))
	for _, path := range files {
		name := filepath.Base(path)
		if !strings.Contains(name, tenantMarker) && !strings.Contains(name, ".legacy.") && !strings.Contains(name, ".invalid.") {
			continue
		}
		if ctx.Err() != nil {
			return false, replayed > 0
		}
		envelopes, err := readAuditRecovery(path)
		if err != nil {
			auditRecoveryReplayFailures.Add(1)
			log.Printf("[AUDIT] recovery read failed path=%s err=%v", path, err)
			continue
		}
		if len(envelopes) == 0 || envelopes[0].Event.TenantID != tenantID {
			continue
		}
		for _, envelope := range envelopes {
			if envelope.Event.TenantID != tenantID {
				err = fmt.Errorf("recovery file spans multiple tenants")
				break
			}
		}
		completed := 0
		if err == nil {
			for completed < len(envelopes) && replayed < auditRecoveryReplayLimit && ctx.Err() == nil {
				if err = persist(ctx, envelopes[completed].Event); err != nil {
					break
				}
				completed++
				replayed++
			}
			if completed == len(envelopes) {
				err = removeAuditRecovery(path)
			} else if completed > 0 {
				err = errors.Join(err, checkpointAuditRecovery(path, envelopes[completed:]))
			}
		}
		if err != nil {
			auditRecoveryReplayFailures.Add(1)
			log.Printf("[AUDIT] recovery replay failed path=%s tenant=%s err=%v", path, tenantID, err)
			continue
		}
		if replayed >= auditRecoveryReplayLimit {
			return true, true
		}
	}
	return false, replayed > 0
}

type auditRecoveryRequest struct {
	ctx      context.Context
	tenantID string
	task     *pendingAuditEvent
}

var auditRecoveryQueue struct {
	sync.Mutex
	running bool
	pending map[string]struct{}
	dirty   map[string]bool
	items   []auditRecoveryRequest
}

const auditRecoveryQueueLimit = 64
const auditRecoveryScanInterval = 30 * time.Second

var auditRecoveryAdmissions = make(chan struct{}, auditRecoveryQueueLimit)
var auditRecoveryScanOffset atomic.Uint64

func scheduleAuditRecoveryBacklog(ctx context.Context) {
	files, err := auditRecoveryFiles()
	if err != nil {
		auditRecoveryScanFailures.Add(1)
		log.Printf("[AUDIT] recovery scan failed: %v", err)
		return
	}
	seen := make(map[string]struct{})
	tenants := make([]string, 0, len(files))
	for _, path := range files {
		envelopes, err := readAuditRecovery(path)
		if os.IsNotExist(err) {
			continue
		}
		if err == nil && (len(envelopes) == 0 || envelopes[0].Event.TenantID == "") {
			err = fmt.Errorf("recovery file has no tenant")
		}
		if err != nil {
			auditRecoveryScanFailures.Add(1)
			log.Printf("[AUDIT] recovery discovery failed path=%s err=%v", path, err)
			continue
		}
		tenantID := envelopes[0].Event.TenantID
		if _, ok := seen[tenantID]; !ok {
			seen[tenantID] = struct{}{}
			tenants = append(tenants, tenantID)
		}
	}
	limit := min(len(tenants), cap(auditRecoveryAdmissions))
	if limit == 0 {
		return
	}
	start := int((auditRecoveryScanOffset.Add(uint64(limit)) - uint64(limit)) % uint64(len(tenants)))
	for index := range limit {
		if ctx.Err() != nil {
			return
		}
		scheduleAuditRecoveryIfIdle(ctx, tenants[(start+index)%len(tenants)])
	}
}

func runAuditRecoveryScanner(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for ctx.Err() == nil {
		scheduleAuditRecoveryBacklog(ctx)
		select {
		case <-ctx.Done():
		case <-ticker.C:
		}
	}
}

func scheduleAuditRecovery(ctx context.Context, tenantID string) {
	scheduleAuditRecoveryTask(ctx, tenantID, true)
}

func scheduleAuditRecoveryIfIdle(ctx context.Context, tenantID string) {
	scheduleAuditRecoveryTask(ctx, tenantID, false)
}

func scheduleAuditRecoveryTask(ctx context.Context, tenantID string, reschedule bool) {
	auditRecoveryQueue.Lock()
	if _, pending := auditRecoveryQueue.pending[tenantID]; pending {
		if reschedule {
			auditRecoveryQueue.dirty[tenantID] = true
		}
		auditRecoveryQueue.Unlock()
		return
	}
	auditRecoveryQueue.Unlock()
	select {
	case auditRecoveryAdmissions <- struct{}{}:
	default:
		return
	}
	auditAsync.Lock()
	if auditAsync.closing {
		auditAsync.Unlock()
		<-auditRecoveryAdmissions
		return
	}
	auditRecoveryQueue.Lock()
	if _, pending := auditRecoveryQueue.pending[tenantID]; pending {
		if reschedule {
			auditRecoveryQueue.dirty[tenantID] = true
		}
		auditRecoveryQueue.Unlock()
		auditAsync.Unlock()
		<-auditRecoveryAdmissions
		return
	}
	ctx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	task := &pendingAuditEvent{cancel: cancel}
	ctx = context.WithValue(ctx, pendingAuditContextKey{}, task)
	if auditAsync.active == nil {
		auditAsync.active = make(map[*pendingAuditEvent]struct{})
	}
	auditAsync.active[task] = struct{}{}
	startPendingAudit()
	if auditRecoveryQueue.pending == nil {
		auditRecoveryQueue.pending = make(map[string]struct{})
		auditRecoveryQueue.dirty = make(map[string]bool)
	}
	auditRecoveryQueue.pending[tenantID] = struct{}{}
	auditRecoveryQueue.items = append(auditRecoveryQueue.items, auditRecoveryRequest{ctx, tenantID, task})
	start := !auditRecoveryQueue.running
	auditRecoveryQueue.running = true
	auditRecoveryQueue.Unlock()
	auditAsync.Unlock()
	if start {
		go runAuditRecoveryQueue()
	}
}

func runAuditRecoveryQueue() {
	for {
		auditRecoveryQueue.Lock()
		if len(auditRecoveryQueue.items) == 0 {
			auditRecoveryQueue.running = false
			auditRecoveryQueue.Unlock()
			return
		}
		request := auditRecoveryQueue.items[0]
		auditRecoveryQueue.items = auditRecoveryQueue.items[1:]
		auditRecoveryQueue.Unlock()

		ctx, stop := context.WithTimeout(request.ctx, 5*time.Second)
		more, restored := replayAuditRecovery(ctx, request.tenantID, auditRecoveryPersist)
		if restored && ctx.Err() == nil {
			if err := auditRecoveryPublish(ctx, request.tenantID, auditRecoveryReplayLimit); err != nil {
				log.Printf("[AUDIT] recovery transport publish failed tenant=%s err=%v", request.tenantID, err)
			}
		}
		stop()
		auditRecoveryQueue.Lock()
		auditRecoveryQueue.dirty[request.tenantID] = auditRecoveryQueue.dirty[request.tenantID] || more
		if auditRecoveryQueue.dirty[request.tenantID] && request.ctx.Err() == nil {
			auditRecoveryQueue.dirty[request.tenantID] = false
			auditRecoveryQueue.items = append(auditRecoveryQueue.items, request)
			auditRecoveryQueue.Unlock()
			continue
		}
		delete(auditRecoveryQueue.dirty, request.tenantID)
		delete(auditRecoveryQueue.pending, request.tenantID)
		auditRecoveryQueue.Unlock()
		<-auditRecoveryAdmissions
		finishPendingAudit(request.task)
	}
}

// EmitAuditEvent appends in Postgres, then publishes committed outbox rows.
func EmitAuditEvent(ctx context.Context, event *AuditEvent) error {
	if err := persistAuditMetadata(ctx, event); err != nil {
		auditPostgresFailures.Add(1)
		if strings.Contains(err.Error(), "idempotency-key collision") {
			auditIdempotencyCollisions.Add(1)
		}
		log.Printf("[AUDIT] Postgres metadata persistence failed: %v", err)
		outboxAvailable, outboxErr := recoverAuditEvent(ctx, event, err)
		if outboxErr != nil {
			auditOutboxFailures.Add(1)
			log.Printf("[AUDIT] Durable outbox write failed: %v", outboxErr)
		}
		if auditFailClosedEnabled() {
			auditFailClosedFailures.Add(1)
			return &auditPersistenceError{
				cause:             fmt.Errorf("canonical audit append failed (local recovery copy available=%t): %w", outboxAvailable, err),
				recoveryAvailable: outboxAvailable,
			}
		}
		auditFailOpenLosses.Add(1)
		log.Printf("[AUDIT] class=%s provider=%s result=fail_open recovery_available=%t err=%v", event.Action, event.Provider, outboxAvailable, err)
		return nil
	}
	defer scheduleAuditRecovery(ctx, event.TenantID)

	// Attempt transport publish first.
	if err := publishPendingAuditOutbox(ctx, event.TenantID, 100); err != nil {
		log.Printf("[AUDIT] transport publish error: %v — falling back to stdout", err)
		logToStdout(event)
		return nil
	}

	// If the configured transport is unavailable, also log to stdout as fallback.
	if !AuditTransportEnabled() {
		logToStdout(event)
	}
	return nil
}

func auditIdempotencyKey(requestID, eventClass string) string {
	if strings.TrimSpace(requestID) == "" {
		return ""
	}
	return "gateway:" + requestID + ":" + eventClass
}

func emitRequiredDecision(w http.ResponseWriter, r *http.Request, event *AuditEvent, eventClass string) bool {
	if event.IdempotencyKey == "" {
		event.IdempotencyKey = auditIdempotencyKey(event.RequestID, "decision:"+eventClass)
	}
	if err := auditEventEmitter(r.Context(), event); err != nil {
		if auditFailClosedEnabled() {
			log.Printf("[AUDIT] class=%s route=%s provider=%s result=fail_closed err=%v", eventClass, r.URL.Path, event.Provider, err)
			writeGatewayError(w, http.StatusServiceUnavailable, "AuditUnavailable", "Audit persistence is temporarily unavailable.")
			return false
		}
		auditFailOpenLosses.Add(1)
		log.Printf("[AUDIT] class=%s route=%s provider=%s result=fail_open err=%v", eventClass, r.URL.Path, event.Provider, err)
	}
	return true
}

func requireProviderAttempt(w http.ResponseWriter, r *http.Request, event *AuditEvent) bool {
	event.Action = "provider_attempt"
	event.DecisionReason = "Provider egress authorized"
	event.IdempotencyKey = auditIdempotencyKey(event.RequestID, "provider_attempt")
	if !auditFailClosedEnabled() {
		emitAuditTelemetry(r.Context(), event, "provider_attempt")
		return true
	}
	return emitRequiredDecision(w, r, event, "provider_attempt")
}

func emitAuditTelemetry(ctx context.Context, event *AuditEvent, eventClass string) {
	if event.IdempotencyKey == "" {
		event.IdempotencyKey = auditIdempotencyKey(event.RequestID, "telemetry:"+eventClass)
	}
	EmitAuditEventAsync(ctx, event)
}

func emitPostResponseOutcome(ctx context.Context, route string, event *AuditEvent) {
	event.IdempotencyKey = auditIdempotencyKey(event.RequestID, "provider_outcome")
	if !auditFailClosedEnabled() {
		EmitAuditEventAsync(ctx, event)
		return
	}
	if err := auditEventEmitter(ctx, event); err != nil {
		auditPostResponseFailures.Add(1)
		var persistenceErr *auditPersistenceError
		if !errors.As(err, &persistenceErr) || !persistenceErr.recoveryAvailable {
			if recoveryErr := writeAuditOutbox(event, err); recoveryErr != nil {
				auditOutboxFailures.Add(1)
				log.Printf("[AUDIT] class=provider_outcome route=%s provider=%s result=recovery_failed err=%v", route, event.Provider, recoveryErr)
			}
		}
		log.Printf("[AUDIT] class=provider_outcome route=%s provider=%s result=post_response_failure err=%v", route, event.Provider, err)
	}
}

const auditAsyncBacklogLimit = 64

var auditAsyncSlots = make(chan struct{}, 4)

type auditRecoveryState uint8

const (
	auditRecoveryPending auditRecoveryState = iota
	auditRecoveryClaimed
	auditRecoveryDurable
	auditRecoveryIndeterminate
)

type pendingAuditEvent struct {
	recovery      *AuditEvent
	recoveryState auditRecoveryState
	recoveryErr   error
	spillDone     chan struct{}
	cancel        context.CancelFunc
}

type pendingAuditContextKey struct{}

var auditAsync struct {
	sync.Mutex
	pending int
	drained chan struct{}
	closing bool
	active  map[*pendingAuditEvent]struct{}
}

func startPendingAudit() {
	if auditAsync.pending == 0 {
		auditAsync.drained = make(chan struct{})
	}
	auditAsync.pending++
}

func finishPendingAudit(task *pendingAuditEvent) {
	auditAsync.Lock()
	delete(auditAsync.active, task)
	auditAsync.pending--
	if auditAsync.pending == 0 {
		close(auditAsync.drained)
	}
	auditAsync.Unlock()
	if task != nil {
		task.cancel()
	}
}

func recoverAuditEvent(ctx context.Context, event *AuditEvent, cause error) (bool, error) {
	task, _ := ctx.Value(pendingAuditContextKey{}).(*pendingAuditEvent)
	if task == nil {
		err := writeAuditOutbox(event, cause)
		return err == nil, err
	}
	return recoverPendingAuditEvent(task, event, cause)
}

func recoverPendingAuditEvent(task *pendingAuditEvent, event *AuditEvent, cause error) (bool, error) {
	for {
		auditAsync.Lock()
		switch task.recoveryState {
		case auditRecoveryDurable:
			auditAsync.Unlock()
			return true, nil
		case auditRecoveryClaimed:
			done := task.spillDone
			auditAsync.Unlock()
			<-done
		case auditRecoveryIndeterminate:
			err := task.recoveryErr
			auditAsync.Unlock()
			return false, err
		default:
			task.recoveryState = auditRecoveryClaimed
			task.spillDone = make(chan struct{})
			auditAsync.Unlock()
			err := writeAuditOutbox(event, cause)
			auditAsync.Lock()
			if err == nil {
				task.recoveryState = auditRecoveryDurable
			} else {
				var indeterminate *auditOutboxIndeterminateError
				if errors.As(err, &indeterminate) {
					task.recoveryState, task.recoveryErr = auditRecoveryIndeterminate, err
				} else {
					task.recoveryState = auditRecoveryPending
				}
			}
			close(task.spillDone)
			task.spillDone = nil
			auditAsync.Unlock()
			return err == nil, err
		}
	}
}

func auditRecoveryFinalized(task *pendingAuditEvent) bool {
	for {
		auditAsync.Lock()
		state, done := task.recoveryState, task.spillDone
		auditAsync.Unlock()
		if state == auditRecoveryDurable || state == auditRecoveryIndeterminate {
			return true
		}
		if state != auditRecoveryClaimed {
			return false
		}
		<-done
	}
}

func auditOperationContext(parent context.Context) context.Context {
	if _, tracked := parent.Value(pendingAuditContextKey{}).(*pendingAuditEvent); tracked {
		return parent
	}
	return context.WithoutCancel(parent)
}

func drainAuditEvents(ctx context.Context) error {
	auditAsync.Lock()
	auditAsync.closing = true
	pending, done := auditAsync.pending, auditAsync.drained
	auditAsync.Unlock()
	if pending == 0 {
		return nil
	}
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		err := fmt.Errorf("audit drain: %w", ctx.Err())
		auditAsync.Lock()
		tasksByTenant := make(map[string][]*pendingAuditEvent)
		cancels := make([]context.CancelFunc, 0, len(auditAsync.active))
		for task := range auditAsync.active {
			if task.recovery == nil {
				cancels = append(cancels, task.cancel)
				continue
			}
			if task.recoveryState != auditRecoveryPending {
				continue
			}
			task.recoveryState = auditRecoveryClaimed
			task.spillDone = make(chan struct{})
			tasksByTenant[task.recovery.TenantID] = append(tasksByTenant[task.recovery.TenantID], task)
			cancels = append(cancels, task.cancel)
		}
		auditAsync.Unlock()
		for _, cancel := range cancels {
			cancel()
		}
		for _, tasks := range tasksByTenant {
			spill := make([]*AuditEvent, len(tasks))
			for index, task := range tasks {
				spill[index] = task.recovery
			}
			spillErr := writeAuditOutboxBatch(spill, err)
			auditAsync.Lock()
			for _, task := range tasks {
				var indeterminate *auditOutboxIndeterminateError
				if spillErr == nil {
					task.recoveryState = auditRecoveryDurable
				} else if errors.As(spillErr, &indeterminate) {
					task.recoveryState, task.recoveryErr = auditRecoveryIndeterminate, spillErr
				} else {
					task.recoveryState = auditRecoveryPending
				}
				close(task.spillDone)
				task.spillDone = nil
			}
			auditAsync.Unlock()
			if spillErr != nil {
				auditOutboxFailures.Add(1)
				err = errors.Join(err, spillErr)
				var indeterminate *auditOutboxIndeterminateError
				if !errors.As(spillErr, &indeterminate) {
					for _, task := range tasks {
						if _, retryErr := recoverPendingAuditEvent(task, task.recovery, spillErr); retryErr != nil {
							auditOutboxFailures.Add(1)
							err = errors.Join(err, retryErr)
						}
					}
				}
			}
		}
		return err
	}
}

func EmitAuditEventAsync(ctx context.Context, event *AuditEvent) {
	if event == nil {
		log.Print("[AUDIT] async emit rejected nil event")
		return
	}
	auditAsync.Lock()
	if auditAsync.closing {
		auditAsync.Unlock()
		if err := writeAuditOutbox(event, errors.New("gateway shutting down")); err != nil {
			auditOutboxFailures.Add(1)
			log.Printf("[AUDIT] shutdown recovery failed: %v", err)
		}
		return
	}
	ctx = context.WithoutCancel(ctx)
	if auditFailClosedEnabled() {
		startPendingAudit()
		auditAsync.Unlock()
		defer finishPendingAudit(nil)
		if err := EmitAuditEvent(ctx, event); err != nil {
			log.Printf("[AUDIT] fail-closed emit failed: %v", err)
		}
		return
	}
	if len(auditAsync.active) >= auditAsyncBacklogLimit {
		auditAsync.Unlock()
		if err := writeAuditOutbox(event, errors.New("asynchronous audit backlog capacity exhausted")); err != nil {
			auditOutboxFailures.Add(1)
			log.Printf("[AUDIT] overload recovery failed: %v", err)
		}
		return
	}
	recovery := *event
	recovery.FrameworksAffected = append([]string(nil), event.FrameworksAffected...)
	recovery.ExecutionTrace = append([]string(nil), event.ExecutionTrace...)
	ctx, cancel := context.WithCancel(ctx)
	task := &pendingAuditEvent{recovery: &recovery, cancel: cancel}
	ctx = context.WithValue(ctx, pendingAuditContextKey{}, task)
	if auditAsync.active == nil {
		auditAsync.active = make(map[*pendingAuditEvent]struct{})
	}
	auditAsync.active[task] = struct{}{}
	startPendingAudit()
	auditAsync.Unlock()
	go func() {
		select {
		case auditAsyncSlots <- struct{}{}:
		case <-ctx.Done():
			if _, err := recoverAuditEvent(ctx, task.recovery, ctx.Err()); err != nil {
				auditOutboxFailures.Add(1)
				log.Printf("[AUDIT] canceled async recovery failed: %v", err)
			}
			finishPendingAudit(task)
			return
		}
		defer func() {
			<-auditAsyncSlots
			finishPendingAudit(task)
		}()
		if auditRecoveryFinalized(task) {
			return
		}
		if cause := ctx.Err(); cause != nil {
			_, err := recoverPendingAuditEvent(task, task.recovery, cause)
			if err != nil {
				auditOutboxFailures.Add(1)
				log.Printf("[AUDIT] canceled async recovery failed: %v", err)
			}
			return
		}
		if err := auditEventEmitter(ctx, event); err != nil {
			log.Printf("[AUDIT] async emit failed: %v", err)
		}
	}()
}

// logToStdout emits a structured JSON audit log to stdout.
func logToStdout(event *AuditEvent) {
	eventBytes, err := json.Marshal(event)
	if err != nil {
		log.Printf("Failed to marshal audit event: %v", err)
		return
	}
	log.Printf("[AUDIT] %s", string(eventBytes))
}

func persistAuditMetadata(parent context.Context, event *AuditEvent) error {
	if event == nil {
		return fmt.Errorf("audit event is nil")
	}
	if event.TenantID == "" || event.ID == "" {
		if !auditFailClosedEnabled() {
			return nil
		}
		return fmt.Errorf("audit event missing tenant_id or id")
	}
	if DB == nil {
		if auditFailClosedEnabled() {
			return fmt.Errorf("database is not initialized")
		}
		return nil
	}

	ctx, cancel := context.WithTimeout(auditOperationContext(parent), 10*time.Second)
	defer cancel()

	err := RunInTenantTx(ctx, event.TenantID, func(tx *sql.Tx) error {
		// RunInTenantTx has authenticated and matched the tenant. The canonical
		// append function still checks this legacy GUC in addition to signed RLS.
		if _, err := tx.ExecContext(ctx, "SELECT set_config('app.current_tenant_id', $1, true)", event.TenantID); err != nil {
			return err
		}
		if event.Timestamp.IsZero() {
			event.Timestamp = time.Now().UTC()
		}
		if event.IdempotencyKey == "" {
			event.IdempotencyKey = event.ID
		}
		executionTrace := "[]"
		trace := append([]string(nil), event.ExecutionTrace...)
		if correlationID, _ := parent.Value(CorrelationIDContextKey).(string); correlationID != "" && len(correlationID) <= 128 {
			trace = append(trace, "client_correlation_id:"+correlationID)
		}
		if len(trace) > 0 {
			if traceBytes, traceErr := json.Marshal(trace); traceErr == nil {
				executionTrace = string(traceBytes)
			}
		}

		var duplicate bool
		return tx.QueryRowContext(ctx, `
			SELECT record_id, tenant_sequence, prior_hash, integrity_hash,
			       canonical_payload, duplicate
			FROM append_audit_event_v2(
				$1::uuid, $2::uuid, $3, $4, NULL, 'gateway', $5, $6,
				NULLIF($7, '')::uuid, $8, $9, $10, $11, $12, $13, $14,
				$15, $16::jsonb
			)
		`,
			event.TenantID,
			event.ID,
			event.IdempotencyKey,
			event.Timestamp,
			event.Action,
			event.RequestID,
			event.PolicyID,
			event.Provider,
			event.Model,
			event.DecisionReason,
			event.PromptCount,
			event.RequestSize,
			event.ResponseStatus,
			event.DurationMs,
			pq.Array(event.FrameworksAffected),
			executionTrace,
		).Scan(
			&event.ID,
			&event.TenantSequence,
			&event.PriorHash,
			&event.IntegrityHash,
			&event.CanonicalPayload,
			&duplicate,
		)
	})
	if err != nil {
		return err
	}
	return nil
}

func publishPendingAuditOutbox(parent context.Context, tenantID string, limit int) error {
	if !AuditTransportEnabled() || DB == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(auditOperationContext(parent), 15*time.Second)
	defer cancel()
	return RunInTenantTx(ctx, tenantID, func(tx *sql.Tx) error {
		var backlog int64
		var oldestAge float64
		if err := tx.QueryRowContext(ctx, `
			SELECT count(*),
			       COALESCE(EXTRACT(EPOCH FROM now() - min(created_at)), 0)
			FROM audit_outbox
			WHERE tenant_id = $1::uuid AND published_at IS NULL
		`, tenantID).Scan(&backlog, &oldestAge); err != nil {
			return err
		}
		auditOutboxBacklog.Store(uint64(backlog))
		auditOutboxOldestAge.Store(uint64(max(oldestAge, 0)))
		rows, err := tx.QueryContext(ctx, `
			SELECT id, event_payload
			FROM audit_outbox
			WHERE tenant_id = $1::uuid AND published_at IS NULL
			ORDER BY tenant_sequence
			FOR UPDATE SKIP LOCKED
			LIMIT $2
		`, tenantID, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		type pending struct {
			id      int64
			payload []byte
		}
		var events []pending
		for rows.Next() {
			var item pending
			if err := rows.Scan(&item.id, &item.payload); err != nil {
				return err
			}
			events = append(events, item)
		}
		if err := rows.Err(); err != nil {
			return err
		}
		for _, item := range events {
			if err := publishAuditOutboxPayloadContext(ctx, tenantID, item.payload); err != nil {
				_, _ = tx.ExecContext(ctx, `
					UPDATE audit_outbox
					SET publish_attempts = publish_attempts + 1, last_error = $2
					WHERE id = $1
				`, item.id, err.Error())
				return err
			}
			if _, err := tx.ExecContext(ctx, `
				UPDATE audit_outbox
				SET published_at = now(), publish_attempts = publish_attempts + 1,
				    last_error = NULL
				WHERE id = $1
			`, item.id); err != nil {
				return err
			}
		}
		auditOutboxBacklog.Store(uint64(max(backlog-int64(len(events)), 0)))
		if backlog <= int64(len(events)) {
			auditOutboxOldestAge.Store(0)
		}
		return nil
	})
}

func auditRecoveryMetrics() (uint64, uint64) {
	files, err := auditRecoveryFiles()
	if err != nil {
		auditRecoveryScanFailures.Add(1)
		return 0, 0
	}
	var backlog uint64
	var oldest time.Time
	for _, path := range files {
		envelopes, readErr := readAuditRecovery(path)
		if readErr != nil || len(envelopes) == 0 {
			if readErr != nil {
				auditRecoveryScanFailures.Add(1)
			}
			backlog++
			if info, statErr := os.Stat(path); statErr == nil && (oldest.IsZero() || info.ModTime().Before(oldest)) {
				oldest = info.ModTime()
			}
			continue
		}
		backlog += uint64(len(envelopes))
		info, _ := os.Stat(path)
		for _, envelope := range envelopes {
			failedAt := envelope.FailedAt
			if failedAt.IsZero() && info != nil {
				failedAt = info.ModTime()
			}
			if !failedAt.IsZero() && (oldest.IsZero() || failedAt.Before(oldest)) {
				oldest = failedAt
			}
		}
	}
	if oldest.IsZero() || oldest.After(time.Now()) {
		return backlog, 0
	}
	return backlog, uint64(time.Since(oldest).Seconds())
}

func AuditMetricsSnapshot() map[string]uint64 {
	recoveryBacklog, recoveryOldestAge := auditRecoveryMetrics()
	return map[string]uint64{
		"authclaw_gateway_audit_postgres_failures_total":      auditPostgresFailures.Load(),
		"authclaw_gateway_audit_outbox_writes_total":          auditOutboxWrites.Load(),
		"authclaw_gateway_audit_outbox_failures_total":        auditOutboxFailures.Load(),
		"authclaw_gateway_audit_fail_closed_failures_total":   auditFailClosedFailures.Load(),
		"authclaw_gateway_audit_idempotency_collisions_total": auditIdempotencyCollisions.Load(),
		"authclaw_gateway_audit_outbox_backlog":               auditOutboxBacklog.Load(),
		"authclaw_gateway_audit_outbox_oldest_age_seconds":    auditOutboxOldestAge.Load(),
		"authclaw_gateway_audit_recovery_backlog":             recoveryBacklog,
		"authclaw_gateway_audit_recovery_oldest_age_seconds":  recoveryOldestAge,
		"authclaw_gateway_audit_replay_failures_total":        auditRecoveryReplayFailures.Load(),
		"authclaw_gateway_audit_recovery_scan_failures_total": auditRecoveryScanFailures.Load(),
		"authclaw_gateway_audit_fail_open_losses_total":       auditFailOpenLosses.Load(),
		"authclaw_gateway_audit_post_response_failures_total": auditPostResponseFailures.Load(),
	}
}
