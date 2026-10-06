package api

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/mred9/mandates/internal/profile"
)

var (
	ErrUnauthenticated = errors.New("api: unauthenticated")
	ErrForbidden       = errors.New("api: insufficient scope")
	ErrRateLimited     = errors.New("api: rate limited")
	ErrInvalidRequest  = errors.New("api: invalid request")
	errNoRoute         = errors.New("api: no such route")
)

// writeError is the only place errors become HTTP statuses. Messages are
// fixed per code so nothing from the error, or the input, reaches the client.
func writeError(w http.ResponseWriter, r *http.Request, log *slog.Logger, err error) {
	status, code, msg := http.StatusInternalServerError, "internal", "internal error"
	switch {
	case errors.Is(err, profile.ErrNotFound), errors.Is(err, errNoRoute):
		status, code, msg = http.StatusNotFound, "not_found", "resource not found"
	case errors.Is(err, profile.ErrInvalid), errors.Is(err, ErrInvalidRequest):
		status, code, msg = http.StatusBadRequest, "invalid_request", "invalid request"
	case errors.Is(err, ErrUnauthenticated):
		status, code, msg = http.StatusUnauthorized, "unauthenticated", "a valid bearer token is required"
		w.Header().Set("WWW-Authenticate", "Bearer")
	case errors.Is(err, ErrForbidden):
		status, code, msg = http.StatusForbidden, "insufficient_scope", "token lacks the required scope"
	case errors.Is(err, ErrRateLimited):
		status, code, msg = http.StatusTooManyRequests, "rate_limited", "too many requests"
	default:
		log.ErrorContext(r.Context(), "request failed", "request_id", requestID(r.Context()), "error", err.Error())
	}
	type body struct {
		Code      string `json:"code"`
		Message   string `json:"message"`
		RequestID string `json:"request_id"`
	}
	writeJSON(w, status, map[string]body{"error": {code, msg, requestID(r.Context())}})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store") // responses carry PII
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
