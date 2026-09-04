package main

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

type GatewayApprovalPayload struct {
	RequestID    string   `json:"request_id"`
	Provider     string   `json:"provider"`
	Model        string   `json:"model"`
	RuleName     string   `json:"rule_name"`
	Reason       string   `json:"reason"`
	Severity     string   `json:"severity"`
	PromptCount  int      `json:"prompt_count"`
	PromptHashes []string `json:"prompt_hashes"`
	MatchHash    string   `json:"match_hash"`
}

func promptHashes(prompts []string) []string {
	hashes := make([]string, 0, len(prompts))
	for _, prompt := range prompts {
		sum := sha256.Sum256([]byte(prompt))
		hashes = append(hashes, hex.EncodeToString(sum[:]))
	}
	return hashes
}

func hitlTimeout(rule RegexRule) time.Duration {
	if rule.HITLTimeoutSeconds <= 0 {
		return 30 * time.Minute
	}
	timeout := time.Duration(rule.HITLTimeoutSeconds) * time.Second
	if timeout > 30*time.Minute {
		return 30 * time.Minute
	}
	if timeout < 10*time.Second {
		return 10 * time.Second
	}
	return timeout
}

func CreateGatewayApproval(ctx context.Context, tenantID, requesterID, requestID, provider, model string, prompts []string, match *ApprovalRuleMatch) (string, time.Duration, error) {
	if match == nil {
		return "", 0, fmt.Errorf("approval rule match is required")
	}
	if requesterID == "" {
		return "", 0, fmt.Errorf("requester user id missing from gateway auth context")
	}

	timeout := hitlTimeout(match.Rule)
	payload := GatewayApprovalPayload{
		RequestID:    requestID,
		Provider:     provider,
		Model:        model,
		RuleName:     match.Rule.Name,
		Reason:       match.Rule.Reason,
		Severity:     match.Rule.Severity,
		PromptCount:  len(prompts),
		PromptHashes: promptHashes(prompts),
		MatchHash:    match.MatchHash,
	}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return "", 0, err
	}

	approvalID := ""
	err = RunInTenantTx(ctx, tenantID, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, `
			INSERT INTO pending_approvals (
				id, tenant_id, action_id, action_type, action_description,
				action_payload, status, requester_id, expires_at, created_at, updated_at
			)
			VALUES (
				gen_random_uuid(), $1, $2, 'gateway_policy_egress',
				$3, $4::json, 'PENDING', $5, NOW() + $6::interval, NOW(), NOW()
			)
			RETURNING id
		`,
			tenantID,
			requestID,
			fmt.Sprintf("Gateway request requires approval: %s", match.Rule.Reason),
			string(payloadBytes),
			requesterID,
			fmt.Sprintf("%d seconds", int(timeout.Seconds())),
		).Scan(&approvalID)
	})
	if err != nil {
		return "", 0, err
	}
	queueNotification(
		ctx,
		tenantID,
		"",
		"approval_requested",
		"warning",
		"Gateway approval requested",
		fmt.Sprintf("%s requires approval for %s.", provider, model),
		"/agent",
	)

	return approvalID, timeout, nil
}

func ExpireGatewayApproval(ctx context.Context, tenantID, approvalID string) error {
	return RunInTenantTx(ctx, tenantID, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `
			UPDATE pending_approvals
			SET status = 'EXPIRED', updated_at = NOW()
			WHERE tenant_id = $1 AND id = $2 AND status = 'PENDING'
		`, tenantID, approvalID)
		return err
	})
}

func WaitForGatewayApproval(ctx context.Context, tenantID, approvalID string, timeout time.Duration) (string, error) {
	deadline := time.Now().Add(timeout)
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		var status string
		err := RunInTenantTx(ctx, tenantID, func(tx *sql.Tx) error {
			return tx.QueryRowContext(ctx,
				"SELECT status FROM pending_approvals WHERE tenant_id = $1 AND id = $2",
				tenantID,
				approvalID,
			).Scan(&status)
		})
		if err != nil {
			return "", err
		}

		switch status {
		case "APPROVED", "REJECTED", "EXPIRED":
			return status, nil
		}

		if time.Now().After(deadline) {
			if err := ExpireGatewayApproval(ctx, tenantID, approvalID); err != nil {
				return "", err
			}
			return "EXPIRED", nil
		}

		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-ticker.C:
		}
	}
}
