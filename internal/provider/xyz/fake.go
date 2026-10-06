package xyz

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/mred9/mandates/internal/provider"
	"github.com/mred9/mandates/internal/provider/providertest"
)

// NewFake serves XYZ's wire format: {"data": {...}}, or {"data": null} for no match.
func NewFake(t testing.TB, people ...provider.Identity) *providertest.Fake {
	return providertest.New(t, func(w http.ResponseWriter, id *provider.Identity) {
		var p *person
		if id != nil {
			a := id.Address
			p = &person{id.Name, id.Phone, address{a.StreetAddress, a.Locality, a.Region, a.PostalCode, a.Country}}
		}
		json.NewEncoder(w).Encode(map[string]*person{"data": p})
	}, people...)
}
