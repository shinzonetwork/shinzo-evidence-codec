package rule

import (
	"errors"
	"testing"

	"github.com/shinzonetwork/shinzo-evidence-codec/trust"
)

func TestNewRejects(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		alter   func(c *trust.Chain)
		wantErr error
	}{
		{"unknown family", func(c *trust.Chain) { c.Family = "tron" }, ErrUnknownFamily},
		{"required 0", func(c *trust.Chain) { c.SignerSets[0].Required = 0 }, trust.ErrRequired},
		{"reference with a leading zero", func(c *trust.Chain) { c.ID = "eip155:01" }, ErrSettings},
		{"another namespace", func(c *trust.Chain) { c.ID = "bip122:000000000019d6689c085ae165831e93" }, ErrSettings},
		{"chain settings", func(c *trust.Chain) { c.Settings = []byte(`{}`) }, ErrSettings},
		{"asset id with 0x", func(c *trust.Chain) { c.Assets[0].ID = "0x" + usd1 }, ErrSettings},
		{"asset id in mixed case", func(c *trust.Chain) { c.Assets[0].ID = "8D0D000Ee44948FC98c9B98A4FA4921476f08B0d" }, ErrSettings},
		{"no supplySlot", func(c *trust.Chain) { c.Assets[0].Settings = []byte(`{}`) }, ErrSettings},
		{"no settings", func(c *trust.Chain) { c.Assets[0].Settings = nil }, ErrSettings},
		{"unknown setting", func(c *trust.Chain) { c.Assets[0].Settings = []byte(`{"supplySlot": "0x35", "x": 1}`) }, ErrSettings},
		{"supplySlot in another case", func(c *trust.Chain) { c.Assets[0].Settings = []byte(`{"SupplySlot": "0x35"}`) }, ErrSettings},
		{"supplySlot not hex", func(c *trust.Chain) { c.Assets[0].Settings = []byte(`{"supplySlot": "35"}`) }, ErrSettings},
	}
	for _, tc := range cases {
		c := newFixture(t).chain
		tc.alter(&c)
		if _, err := New(c); !errors.Is(err, tc.wantErr) {
			t.Errorf("%s: New = %v, want %v", tc.name, err, tc.wantErr)
		}
	}
}
