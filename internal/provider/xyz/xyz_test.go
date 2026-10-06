package xyz

import (
	"errors"
	"testing"

	"github.com/mred9/mandates/internal/provider"
)

// The wire format is written out literally, so a field-name mistake shared by
// the adapter and its fake still fails here.
func TestDecode(t *testing.T) {
	got, err := decode([]byte(`{"data":{"full_name":"Ada Lovelace","phone_number":"+44 20 7946 0958","address":
		{"line1":"12 St James's Square","city":"London","state":"","zip":"SW1Y 4JH","country_code":"gb"}}}`))
	want := provider.Identity{Name: "Ada Lovelace", Phone: "+44 20 7946 0958", Address: provider.Address{
		StreetAddress: "12 St James's Square", Locality: "London", PostalCode: "SW1Y 4JH", Country: "gb"}}
	if err != nil || got != want {
		t.Fatalf("got %+v, %v\nwant %+v", got, err, want)
	}

	if _, err := decode([]byte(`{"data":null}`)); !errors.Is(err, provider.ErrNotFound) {
		t.Fatalf("null data: got %v, want ErrNotFound", err)
	}
	for _, body := range []string{`{}`, `{"error":"quota exceeded"}`} { // not an answer, so not "no match"
		if _, err := decode([]byte(body)); err == nil || errors.Is(err, provider.ErrNotFound) {
			t.Errorf("%s: got %v, want a malformed-response error", body, err)
		}
	}
}
