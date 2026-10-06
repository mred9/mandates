// Package xyz adapts identity provider XYZ. Its response shape is assumed
// (SPEC §3.2) to differ from ABC's, so the mapping here does real work.
package xyz

import (
	"encoding/json"
	"errors"

	"github.com/mred9/mandates/internal/provider"
)

const Name = "xyz"

type request struct {
	Phone string `json:"phone"`
	Name  string `json:"name"`
}

type address struct {
	Line1       string `json:"line1"`
	City        string `json:"city"`
	State       string `json:"state"`
	Zip         string `json:"zip"`
	CountryCode string `json:"country_code"`
}

type person struct {
	FullName    string  `json:"full_name"`
	PhoneNumber string  `json:"phone_number"`
	Address     address `json:"address"`
}

type response struct {
	Data json.RawMessage `json:"data"` // null means no match; absent means a malformed answer
}

func New(cfg provider.VendorConfig, s provider.Secrets) (*provider.Client, error) {
	return provider.New(Name, cfg, s, encode, decode)
}

func encode(r provider.LookupRequest) any { return request{r.Phone, r.Name} }

// decode maps a 200 answer. XYZ says "no match" with {"data": null}.
func decode(body []byte) (provider.Identity, error) {
	var r response
	if err := json.Unmarshal(body, &r); err != nil {
		return provider.Identity{}, err
	}
	if r.Data == nil {
		return provider.Identity{}, errors.New("xyz: no data field")
	}
	var p *person
	if err := json.Unmarshal(r.Data, &p); err != nil {
		return provider.Identity{}, err
	}
	if p == nil {
		return provider.Identity{}, provider.ErrNotFound
	}
	a := p.Address
	return provider.Identity{Name: p.FullName, Phone: p.PhoneNumber, Address: provider.Address{
		StreetAddress: a.Line1, Locality: a.City, Region: a.State, PostalCode: a.Zip, Country: a.CountryCode,
	}}, nil
}
