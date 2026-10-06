package api

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/mred9/mandates/internal/profile"
)

const defaultPageSize = 20

type profileJSON struct {
	ID        string          `json:"id"`
	Name      string          `json:"name"`
	Phone     string          `json:"phone"`
	Address   profile.Address `json:"address"`
	CreatedAt time.Time       `json:"created_at"`
}

func toJSON(p profile.Profile) profileJSON {
	return profileJSON{p.ID, p.Name, p.Phone, p.Address, p.CreatedAt}
}

func (a *api) getProfile(w http.ResponseWriter, r *http.Request) error {
	p, err := a.cfg.Profiles.Get(r.Context(), r.PathValue("id"))
	if errors.Is(err, profile.ErrNotFound) {
		if aerr := a.audit(r, "profile.get", nil, "not_found"); aerr != nil {
			return aerr
		}
		return profile.ErrNotFound // the same 404 whether the ID was unknown or malformed
	}
	if err != nil {
		return err
	}
	if err := a.audit(r, "profile.get", []string{p.ID}, "returned"); err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, toJSON(p))
	return nil
}

type searchRequest struct {
	Phone     string `json:"phone"`
	PageSize  int    `json:"page_size"`
	PageToken string `json:"page_token"` // base64url of the last ID returned; no PII
}

type searchResponse struct {
	Items         []profileJSON `json:"items"`
	NextPageToken string        `json:"next_page_token,omitempty"`
}

// searchProfiles takes the phone in the body so it never lands in URLs,
// proxy logs or browser history.
func (a *api) searchProfiles(w http.ResponseWriter, r *http.Request) error {
	var req searchRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		return fmt.Errorf("%w: body: %v", ErrInvalidRequest, err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return fmt.Errorf("%w: trailing data", ErrInvalidRequest)
	}
	if req.PageSize == 0 {
		req.PageSize = defaultPageSize
	}
	after, err := base64.RawURLEncoding.DecodeString(req.PageToken)
	if err != nil {
		return fmt.Errorf("%w: page_token", ErrInvalidRequest)
	}
	ps, err := a.cfg.Profiles.Search(r.Context(), req.Phone, string(after), req.PageSize)
	if err != nil {
		return err
	}

	res := searchResponse{Items: make([]profileJSON, 0, len(ps))}
	var ids []string
	for _, p := range ps {
		res.Items = append(res.Items, toJSON(p))
		ids = append(ids, p.ID)
	}
	outcome := "returned"
	if len(ps) == 0 {
		outcome = "empty"
	}
	if len(ps) == req.PageSize { // a full page: there may be more
		res.NextPageToken = base64.RawURLEncoding.EncodeToString([]byte(ps[len(ps)-1].ID))
	}
	if err := a.audit(r, "profile.search", ids, outcome); err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, res)
	return nil
}

// audit records a PII read. Handlers call it before writing any PII and fail
// closed if it errors.
func (a *api) audit(r *http.Request, action string, ids []string, outcome string) error {
	s := state(r.Context())
	err := a.cfg.Auditor.Record(r.Context(), AuditEvent{
		Time: time.Now().UTC(), RequestID: s.id, ClientID: s.clientID,
		Action: action, SubjectIDs: ids, Outcome: outcome,
	})
	if err != nil {
		return fmt.Errorf("api: audit: %w", err)
	}
	return nil
}
