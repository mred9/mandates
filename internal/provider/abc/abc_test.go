package abc

import (
	"testing"

	"github.com/mred9/mandates/internal/provider"
)

// The wire format is written out literally, so a field-name mistake shared by
// the adapter and its fake still fails here.
func TestDecode(t *testing.T) {
	got, err := decode([]byte(`{"name":"Ada Lovelace","phone":"+44 20 7946 0958","address":
		{"street_address":"12 St James's Square","locality":"London","region":"","postal_code":"SW1Y 4JH","country":"gb"}}`))
	want := provider.Identity{Name: "Ada Lovelace", Phone: "+44 20 7946 0958", Address: provider.Address{
		StreetAddress: "12 St James's Square", Locality: "London", PostalCode: "SW1Y 4JH", Country: "gb"}}
	if err != nil || got != want {
		t.Fatalf("got %+v, %v\nwant %+v", got, err, want)
	}
}
