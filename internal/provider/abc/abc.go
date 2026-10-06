// Package abc adapts identity provider ABC, which uses the brief's schema as is.
package abc

import (
	"encoding/json"

	"github.com/mred9/mandates/internal/provider"
)

const Name = "abc"

type request struct {
	Phone string `json:"phone"`
	Name  string `json:"name"`
}

type address struct {
	StreetAddress string `json:"street_address"`
	Locality      string `json:"locality"`
	Region        string `json:"region"`
	PostalCode    string `json:"postal_code"`
	Country       string `json:"country"`
}

type response struct {
	Name    string  `json:"name"`
	Phone   string  `json:"phone"`
	Address address `json:"address"`
}

func New(cfg provider.VendorConfig, s provider.Secrets) (*provider.Client, error) {
	return provider.New(Name, cfg, s, encode, decode)
}

func encode(r provider.LookupRequest) any { return request{r.Phone, r.Name} }

// decode maps a 200 answer. ABC says "no match" with a 404, which Client handles.
func decode(body []byte) (provider.Identity, error) {
	var r response
	if err := json.Unmarshal(body, &r); err != nil {
		return provider.Identity{}, err
	}
	a := r.Address
	return provider.Identity{Name: r.Name, Phone: r.Phone, Address: provider.Address{
		StreetAddress: a.StreetAddress, Locality: a.Locality, Region: a.Region, PostalCode: a.PostalCode, Country: a.Country,
	}}, nil
}
