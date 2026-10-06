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

// Record writes through the handler directly: Logger.Info drops write errors,
// and an audit write that fails silently would defeat failing closed.
func (a SlogAuditor) Record(ctx context.Context, e AuditEvent) error {
	r := slog.NewRecord(time.Now(), slog.LevelInfo, "audit", 0)
	r.Add("event_time", e.Time, "request_id", e.RequestID, "client_id", e.ClientID,
		"action", e.Action, "subject_ids", e.SubjectIDs, "outcome", e.Outcome)
	return a.Logger.Handler().Handle(ctx, r)
}
