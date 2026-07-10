package main

import (
	"context"
	"database/sql"
	"log"
	"time"
)

func queueNotification(tenantID, userID, notificationType, severity, title, body, link string) {
	if tenantID == "" {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := insertNotification(ctx, tenantID, userID, notificationType, severity, title, body, link); err != nil {
			log.Printf("notification insert failed: %v", err)
		}
	}()
}

func insertNotification(ctx context.Context, tenantID, userID, notificationType, severity, title, body, link string) error {
	if severity != "info" && severity != "warning" && severity != "critical" {
		severity = "info"
	}
	var userValue interface{}
	if userID != "" {
		userValue = userID
	}
	return RunInTenantTx(ctx, tenantID, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `
			INSERT INTO notifications (id, tenant_id, user_id, type, severity, title, body, link, created_at)
			VALUES (gen_random_uuid(), $1, $2::uuid, $3, $4, $5, $6, $7, NOW())
		`, tenantID, userValue, notificationType, severity, title, body, link)
		return err
	})
}
