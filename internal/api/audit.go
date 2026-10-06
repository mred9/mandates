package api

import (
	"context"
	"log/slog"
	"time"
)

// AuditEvent records who read which profiles. It holds IDs, never PII.
type AuditEvent struct {
	Time       time.Time
	RequestID  string
	ClientID   string
	Action     string   // "profile.get", "profile.search"
	SubjectIDs []string // profile IDs returned
	Outcome    string   // "returned", "not_found", "empty"
}

// Auditor must succeed before PII is returned: handlers fail closed.
type Auditor interface {
	Record(ctx context.Context, e AuditEvent) error
}

// SlogAuditor writes events to a dedicated logger.
// TODO: production ships these to an append-only store, separate from app logs.
type SlogAuditor struct{ Logger *slog.Logger }

func (a SlogAuditor) Record(ctx context.Context, e AuditEvent) error {
	a.Logger.InfoContext(ctx, "audit", "event_time", e.Time, "request_id", e.RequestID, "client_id", e.ClientID,
		"action", e.Action, "subject_ids", e.SubjectIDs, "outcome", e.Outcome)
	return nil
}
