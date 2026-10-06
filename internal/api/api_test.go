package api

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/time/rate"

	"github.com/mred9/mandates/internal/crypto"
	"github.com/mred9/mandates/internal/profile"
	"github.com/mred9/mandates/internal/store/sqlite"
)

// recAuditor records events, or fails every Record when err is set.
type recAuditor struct {
	events []AuditEvent
	err    error
}

func (a *recAuditor) Record(_ context.Context, e AuditEvent) error {
	if a.err != nil {
		return a.err
	}
	a.events = append(a.events, e)
	return nil
}

type fixture struct {
	h      http.Handler
	repo   *profile.Repository
	tokens *DevTokens
	audit  *recAuditor
	logs   *bytes.Buffer
	token  string // profiles:read, client "app"
}

// newFixture serves the real repository on a SQLite file. cfg may adjust the
// Config before the handler is built.
func newFixture(t *testing.T, cfg func(*Config)) *fixture {
	t.Helper()
	db, err := sqlite.Open(context.Background(), filepath.Join(t.TempDir(), "api.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	env, _ := crypto.NewLocalKeyEnvelope(bytes.Repeat([]byte{1}, 32))
	index, _ := crypto.NewBlindIndex(bytes.Repeat([]byte{2}, 32))
	f := &fixture{
		repo:   profile.NewRepository(sqlite.NewProfileStore(db), env, index),
		tokens: NewDevTokens(),
		audit:  &recAuditor{},
		logs:   &bytes.Buffer{},
	}
	f.token = f.mint(t, "app", time.Hour, ScopeProfilesRead)
	c := Config{
		Profiles: f.repo, Tokens: f.tokens, Auditor: f.audit,
		Logger: NewLogger(f.logs), Rate: rate.Inf, Burst: 1,
	}
	if cfg != nil {
		cfg(&c)
	}
	f.h = New(c)
	return f
}

func (f *fixture) mint(t *testing.T, client string, ttl time.Duration, scopes ...string) string {
	t.Helper()
	tok, err := f.tokens.Mint(client, scopes, ttl)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func (f *fixture) create(t *testing.T, name, phone string) profile.Profile {
	t.Helper()
	p, err := f.repo.Create(context.Background(), profile.Profile{
		Name: name, Phone: phone,
		Address: profile.Address{StreetAddress: "12 St James's Square", Locality: "London", Country: "GB"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// do sends a request with the fixture's token unless headers override it.
func (f *fixture) do(method, path, body string, headers ...string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Header.Set("Authorization", "Bearer "+f.token)
	for i := 0; i+1 < len(headers); i += 2 {
		r.Header.Set(headers[i], headers[i+1])
	}
	w := httptest.NewRecorder()
	f.h.ServeHTTP(w, r)
	return w
}

type errorBody struct {
	Error struct{ Code, Message, RequestID string } `json:"error"`
}

func errCode(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	var e errorBody
	if err := json.Unmarshal(w.Body.Bytes(), &e); err != nil {
		t.Fatalf("error body is not the envelope: %q", w.Body)
	}
	return e.Error.Code
}

type searchResult struct {
	Items []struct {
		ID, Name, Phone string
		Address         profile.Address
		CreatedAt       time.Time `json:"created_at"`
	}
	NextPageToken string `json:"next_page_token"`
}

func TestGetProfile(t *testing.T) { // AC1
	f := newFixture(t, nil)
	ada := f.create(t, "Ada Lovelace", "+1 (555) 123-4567")

	w := f.do("GET", "/v1/profiles/"+ada.ID, "")
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	var got map[string]any
	json.Unmarshal(w.Body.Bytes(), &got)
	if got["id"] != ada.ID || got["name"] != "Ada Lovelace" || got["phone"] != "+15551234567" || got["created_at"] == nil {
		t.Errorf("body: %s", w.Body)
	}
	if addr, _ := got["address"].(map[string]any); addr["locality"] != "London" {
		t.Errorf("address: %s", w.Body)
	}
	if cc := w.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control = %q", cc)
	}

	unknown := f.do("GET", "/v1/profiles/0192f2c4-0000-7000-8000-000000000000", "", "X-Request-ID", "same")
	if unknown.Code != 404 || errCode(t, unknown) != "not_found" {
		t.Fatalf("unknown: %d %s", unknown.Code, unknown.Body)
	}
	for _, id := range []string{"not-a-uuid", "%FF", "a%00b"} {
		malformed := f.do("GET", "/v1/profiles/"+id, "", "X-Request-ID", "same")
		if malformed.Code != 404 || !bytes.Equal(unknown.Body.Bytes(), malformed.Body.Bytes()) {
			t.Errorf("%s: %d, body differs:\n%s\n%s", id, malformed.Code, unknown.Body, malformed.Body)
		}
	}
}

func TestSearch(t *testing.T) { // AC2
	f := newFixture(t, nil)
	var want []string
	for _, phone := range []string{"+15551234567", "+1 555 123 4567", "+1 (555) 123-4567"} {
		want = append(want, f.create(t, "Ada Lovelace", phone).ID)
	}
	f.create(t, "Someone Else", "+447700900123")

	var got []string
	token := ""
	for range 3 {
		body, _ := json.Marshal(map[string]any{"phone": "+1-555-123-4567", "page_size": 2, "page_token": token})
		w := f.do("POST", "/v1/profiles/search", string(body))
		if w.Code != 200 {
			t.Fatalf("status %d: %s", w.Code, w.Body)
		}
		var res searchResult
		json.Unmarshal(w.Body.Bytes(), &res)
		for _, it := range res.Items {
			if it.Phone != "+15551234567" || it.Name != "Ada Lovelace" {
				t.Errorf("item: %+v", it)
			}
			got = append(got, it.ID)
		}
		if token = res.NextPageToken; token == "" {
			break
		}
		// The token is the last returned ID and nothing else, so it carries no PII.
		if raw, _ := base64.RawURLEncoding.DecodeString(token); string(raw) != res.Items[len(res.Items)-1].ID {
			t.Errorf("page token %q is not the last returned ID", raw)
		}
	}
	if !slices.Equal(got, want) {
		t.Errorf("paged IDs %v, want %v", got, want)
	}

	w := f.do("POST", "/v1/profiles/search", `{"phone":"+15550000000"}`)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"items":[]`) {
		t.Errorf("no match: %d %s", w.Code, w.Body)
	}
}

func TestSearchRejectsBadInput(t *testing.T) { // AC3
	f := newFixture(t, nil)
	for name, body := range map[string]string{
		"bad json":            `{"phone":`,
		"unknown field":       `{"phone":"+15551234567","name":"Ada"}`,
		"trailing data":       `{"phone":"+15551234567"} {}`,
		"invalid phone":       `{"phone":"555-1234"}`,
		"page size too large": `{"phone":"+15551234567","page_size":101}`,
		"negative page size":  `{"phone":"+15551234567","page_size":-1}`,
		"token not base64":    `{"phone":"+15551234567","page_token":"!!!"}`,
		"token not an ID":     `{"phone":"+15551234567","page_token":"` + base64.RawURLEncoding.EncodeToString([]byte("x")) + `"}`,
		"token a wrapped ID":  `{"phone":"+15551234567","page_token":"` + base64.RawURLEncoding.EncodeToString([]byte("{0192f2c4-0000-7000-8000-000000000000\x00")) + `"}`,
		"body over 16 KiB":    strings.Repeat(" ", 17<<10) + `{"phone":"+15551234567"}`, // valid apart from its size
	} {
		t.Run(name, func(t *testing.T) {
			w := f.do("POST", "/v1/profiles/search", body)
			if w.Code != 400 || errCode(t, w) != "invalid_request" {
				t.Errorf("status %d: %s", w.Code, w.Body)
			}
		})
	}
}

func TestAuth(t *testing.T) { // AC4
	f := newFixture(t, nil)
	expired := f.mint(t, "app", -time.Second, ScopeProfilesRead)
	for name, auth := range map[string]string{
		"missing": "",
		"unknown": "Bearer not-a-real-token",
		"expired": "Bearer " + expired,
		"basic":   "Basic YXBwOnNlY3JldA==",
	} {
		t.Run(name, func(t *testing.T) {
			w := f.do("GET", "/v1/profiles/x", "", "Authorization", auth)
			if w.Code != 401 || errCode(t, w) != "unauthenticated" || w.Header().Get("WWW-Authenticate") != "Bearer" {
				t.Errorf("status %d, WWW-Authenticate %q: %s", w.Code, w.Header().Get("WWW-Authenticate"), w.Body)
			}
		})
	}

	noScope := f.mint(t, "app", time.Hour, "profiles:write")
	for _, req := range [][2]string{{"GET", "/v1/profiles/x"}, {"POST", "/v1/profiles/search"}} {
		w := f.do(req[0], req[1], `{"phone":"+15551234567"}`, "Authorization", "Bearer "+noScope)
		if w.Code != 403 || errCode(t, w) != "insufficient_scope" {
			t.Errorf("%s %s without scope: %d %s", req[0], req[1], w.Code, w.Body)
		}
	}
}

func TestRateLimitPerClient(t *testing.T) { // AC5
	f := newFixture(t, func(c *Config) { c.Rate, c.Burst = rate.Every(time.Hour), 2 })
	other := f.mint(t, "other", time.Hour, ScopeProfilesRead)

	for i := range 2 {
		if w := f.do("GET", "/v1/profiles/x", ""); w.Code != 404 {
			t.Fatalf("request %d: %d", i, w.Code)
		}
	}
	w := f.do("GET", "/v1/profiles/x", "")
	if w.Code != 429 || errCode(t, w) != "rate_limited" || w.Header().Get("Retry-After") == "" {
		t.Errorf("over limit: %d, Retry-After %q: %s", w.Code, w.Header().Get("Retry-After"), w.Body)
	}
	if w := f.do("GET", "/v1/profiles/x", "", "Authorization", "Bearer "+other); w.Code != 404 {
		t.Errorf("other client: %d", w.Code)
	}
}

func TestAuditEveryRead(t *testing.T) { // AC6
	f := newFixture(t, nil)
	ada := f.create(t, "Ada Lovelace", "+15551234567")

	f.do("GET", "/v1/profiles/"+ada.ID, "", "X-Request-ID", "req-1")
	f.do("GET", "/v1/profiles/not-a-uuid", "", "X-Request-ID", "req-2")
	f.do("POST", "/v1/profiles/search", `{"phone":"+15551234567"}`, "X-Request-ID", "req-3")
	f.do("POST", "/v1/profiles/search", `{"phone":"+15550000000"}`, "X-Request-ID", "req-4")

	want := []AuditEvent{
		{RequestID: "req-1", ClientID: "app", Action: "profile.get", SubjectIDs: []string{ada.ID}, Outcome: "returned"},
		{RequestID: "req-2", ClientID: "app", Action: "profile.get", Outcome: "not_found"},
		{RequestID: "req-3", ClientID: "app", Action: "profile.search", SubjectIDs: []string{ada.ID}, Outcome: "returned"},
		{RequestID: "req-4", ClientID: "app", Action: "profile.search", Outcome: "empty"},
	}
	if len(f.audit.events) != len(want) {
		t.Fatalf("got %d events: %+v", len(f.audit.events), f.audit.events)
	}
	for i, e := range f.audit.events {
		if e.Time.IsZero() {
			t.Errorf("event %d has no time", i)
		}
		e.Time = time.Time{}
		if e.RequestID != want[i].RequestID || e.ClientID != want[i].ClientID || e.Action != want[i].Action ||
			e.Outcome != want[i].Outcome || !slices.Equal(e.SubjectIDs, want[i].SubjectIDs) {
			t.Errorf("event %d = %+v, want %+v", i, e, want[i])
		}
	}

	// Fail closed: no audit record, no PII.
	f.audit.err = errors.New("audit sink down")
	for _, w := range []*httptest.ResponseRecorder{
		f.do("GET", "/v1/profiles/"+ada.ID, ""),
		f.do("POST", "/v1/profiles/search", `{"phone":"+15551234567"}`),
	} {
		if w.Code != 500 || strings.Contains(w.Body.String(), "Ada") {
			t.Errorf("audit failure: %d %s", w.Code, w.Body)
		}
	}
}

func TestLogsCarryNoPII(t *testing.T) { // AC7
	f := newFixture(t, nil)
	ada := f.create(t, "Ada Lovelace", "+15551234567")
	f.do("GET", "/v1/profiles/"+ada.ID, "")
	f.do("POST", "/v1/profiles/search", `{"phone":"+1 555 123 4567"}`)
	f.do("POST", "/v1/profiles/search", `{"phone":"+1 555 123 4567"}`, "Authorization", "Bearer junk")

	// Even a careless log call is redacted by key, at any depth.
	log := NewLogger(f.logs)
	log.Info("oops", "phone", "+15551234567", slog.Group("user", "name", "Ada Lovelace"), "authorization", "Bearer "+f.token)
	log.Info("oops", slog.Group("address", "locality", "London"))
	log.WithGroup("phone").Info("oops", "number", "+15551234567")

	out := f.logs.String()
	for _, secret := range []string{"5551234567", "555 123 4567", "Ada Lovelace", "London", f.token} {
		if strings.Contains(out, secret) {
			t.Errorf("logs contain %q:\n%s", secret, out)
		}
	}
	// The access log names the route pattern, not the raw path with the ID in it.
	if !strings.Contains(out, `"route":"GET /v1/profiles/{id}"`) || strings.Contains(out, "/v1/profiles/"+ada.ID) {
		t.Errorf("access log should carry the route pattern:\n%s", out)
	}
}

func TestRequestID(t *testing.T) { // AC7
	f := newFixture(t, nil)
	if got := f.do("GET", "/healthz", "", "X-Request-ID", "abc-123_X").Header().Get("X-Request-ID"); got != "abc-123_X" {
		t.Errorf("well-formed ID not echoed: %q", got)
	}
	for _, bad := range []string{"", "has space", "line\nbreak", strings.Repeat("a", 65)} {
		got := f.do("GET", "/healthz", "", "X-Request-ID", bad).Header().Get("X-Request-ID")
		if got == "" || got == bad {
			t.Errorf("ID %q: got %q, want a generated one", bad, got)
		}
	}
}

// panicky is a Profiles that panics on Get and leaks a secret in its Search error.
type panicky struct{}

func (panicky) Get(context.Context, string) (profile.Profile, error) { panic("boom") }
func (panicky) Search(context.Context, string, string, int) ([]profile.Profile, error) {
	return nil, errors.New("dial db: marker-xyz")
}

func TestInternalErrors(t *testing.T) { // AC8
	f := newFixture(t, func(c *Config) { c.Profiles = panicky{} })
	for _, w := range []*httptest.ResponseRecorder{
		f.do("GET", "/v1/profiles/x", ""),
		f.do("POST", "/v1/profiles/search", `{"phone":"+15551234567"}`),
	} {
		if w.Code != 500 || errCode(t, w) != "internal" || strings.Contains(w.Body.String(), "marker-xyz") {
			t.Errorf("status %d: %s", w.Code, w.Body)
		}
	}
	if !strings.Contains(f.logs.String(), "marker-xyz") || !strings.Contains(f.logs.String(), "boom") {
		t.Errorf("details should be logged:\n%s", f.logs)
	}
}

func TestUnknownRouteUsesEnvelope(t *testing.T) {
	f := newFixture(t, nil)
	w := f.do("GET", "/nope", "")
	if w.Code != 404 || errCode(t, w) != "not_found" {
		t.Errorf("status %d: %s", w.Code, w.Body)
	}
	if w := f.do("GET", "/healthz", "", "Authorization", ""); w.Code != 200 || w.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("healthz: %d, Cache-Control %q", w.Code, w.Header().Get("Cache-Control"))
	}
}

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errors.New("disk full") }

func TestSlogAuditorReportsWriteFailure(t *testing.T) { // AC6
	var buf bytes.Buffer
	e := AuditEvent{Time: time.Now(), RequestID: "r1", ClientID: "app", Action: "profile.get", SubjectIDs: []string{"id-1"}, Outcome: "returned"}
	if err := (SlogAuditor{Logger: NewLogger(&buf)}).Record(context.Background(), e); err != nil || !strings.Contains(buf.String(), `"subject_ids":["id-1"]`) {
		t.Fatalf("Record = %v: %s", err, buf.String())
	}
	if err := (SlogAuditor{Logger: NewLogger(failWriter{})}).Record(context.Background(), e); err == nil {
		t.Error("a failed audit write must return an error, so handlers fail closed")
	}
}
