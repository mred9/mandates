package abc

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/mred9/mandates/internal/provider"
	"github.com/mred9/mandates/internal/provider/providertest"
)

// NewFake serves ABC's wire format: the identity as is, or 404 for no match.
func NewFake(t testing.TB, people ...provider.Identity) *providertest.Fake {
	return providertest.New(t, func(w http.ResponseWriter, id *provider.Identity) {
		if id == nil {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		a := id.Address
		json.NewEncoder(w).Encode(response{id.Name, id.Phone,
			address{a.StreetAddress, a.Locality, a.Region, a.PostalCode, a.Country}})
	}, people...)
}
