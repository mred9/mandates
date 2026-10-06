package api

import (
	"io"
	"log/slog"
	"strings"
)

// redacted are attribute keys whose values never reach the log, at any group depth.
var redacted = map[string]bool{
	"name": true, "phone": true, "address": true, "password": true, "token": true,
	"authorization": true, "secret": true, "street_address": true, "postal_code": true,
}

// NewLogger returns a JSON logger that redacts PII and secrets by key. It is
// the backstop; Profile and Address also redact themselves as LogValuers.
func NewLogger(w io.Writer) *slog.Logger {
	return slog.New(slog.NewJSONHandler(w, &slog.HandlerOptions{
		ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
			if redacted[strings.ToLower(a.Key)] {
				return slog.String(a.Key, "[REDACTED]")
			}
			return a
		},
	}))
}
