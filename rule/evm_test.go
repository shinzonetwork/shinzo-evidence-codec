package rule

import (
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

func TestNewRejects(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		alter   func(c *Config)
		wantErr error
	}{
		{"required 0", func(c *Config) { c.Required = 0 }, ErrRequired},
		{"required above the signers", func(c *Config) { c.Required = len(c.Signers) + 1 }, ErrRequired},
		{"upper-case key", func(c *Config) { c.Signers[0] = strings.ToUpper(c.Signers[0]) }, ErrKey},
		{"uncompressed key", func(c *Config) { c.Signers[0] = uncompressed(t, c.Signers[0]) }, ErrKey},
		{"key not on the curve", func(c *Config) { c.Signers[0] = "02" + strings.Repeat("ff", 32) }, ErrKey},
		{"key listed twice", func(c *Config) { c.Signers[1] = c.Signers[0] }, ErrDuplicateKey},
		{"empty asset id", func(c *Config) { c.Assets[0].ID = "" }, ErrAsset},
		{"asset listed twice", func(c *Config) { c.Assets = append(c.Assets, c.Assets[0]) }, ErrAsset},
		{"another namespace", func(c *Config) { c.Chain = "bip122:000000000019d6689c085ae165831e93" }, ErrUnsupportedChain},
		{"reference with a leading zero", func(c *Config) { c.Chain = "eip155:01" }, ErrSettings},
		{"asset id with 0x", func(c *Config) { c.Assets[0].ID = "0x" + usd1 }, ErrSettings},
		{"asset id in mixed case", func(c *Config) { c.Assets[0].ID = "8D0D000Ee44948FC98c9B98A4FA4921476f08B0d" }, ErrSettings},
		{"no supply slot", func(c *Config) { c.Assets[0].SupplySlot = "" }, ErrSettings},
		{"supply slot not hex", func(c *Config) { c.Assets[0].SupplySlot = "35" }, ErrSettings},
	}
	for _, tc := range cases {
		c := newFixture(t).chain
		tc.alter(&c)
		if _, err := New(c); !errors.Is(err, tc.wantErr) {
			t.Errorf("%s: New = %v, want %v", tc.name, err, tc.wantErr)
		}
	}
}

// uncompressed returns key, a compressed public key in hex, in its 65-byte uncompressed form.
func uncompressed(t *testing.T, key string) string {
	t.Helper()
	b, err := hex.DecodeString(key)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := secp256k1.ParsePubKey(b)
	if err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(pub.SerializeUncompressed())
}
