// Package trust parses the trust file, which lists per chain who may sign statements and how many must agree.
package trust

import (
	"bytes"
	"encoding/hex"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"regexp"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// Version is the trust file format Parse reads.
const Version = 1

// maxSafeInteger is the largest integer every JSON reader holds exactly (RFC 7493, section 2.2).
const maxSafeInteger = 1<<53 - 1

// caip2 is the CAIP-2 chain ID syntax.
var caip2 = regexp.MustCompile(`^[-a-z0-9]{3,8}:[-_a-zA-Z0-9]{1,32}$`)

// Errors returned by Parse.
var (
	ErrVersion        = errors.New("unsupported trust file version")
	ErrNull           = errors.New("null is not allowed")
	ErrNumber         = errors.New("number is not an integer from 0 to 2^53-1")
	ErrMissingFrom    = errors.New("from is missing")
	ErrChainID        = errors.New("chain is not a CAIP-2 ID")
	ErrDuplicateChain = errors.New("chain listed twice")
	ErrFamily         = errors.New("family is missing")
	ErrMaxBlobBytes   = errors.New("maxBlobBytes is 0")
	ErrSignerSets     = errors.New("signer sets are missing or not contiguous")
	ErrRange          = errors.New("signer set ends before it starts")
	ErrRequired       = errors.New("required is not between 1 and the number of keys")
	ErrKey            = errors.New("key is not a lower-case compressed secp256k1 public key")
	ErrDuplicateKey   = errors.New("key listed twice in one signer set")
	ErrAsset          = errors.New("asset id is empty or listed twice")
)

// File is a parsed trust file.
type File struct {
	Version int     `json:"version"`
	Chains  []Chain `json:"chains"`
}

// Chain is one chain's entry.
type Chain struct {
	ID           string         `json:"chain"`
	Family       string         `json:"family"`
	Settings     jsontext.Value `json:"settings"` // checked by the family
	MaxBlobBytes uint64         `json:"maxBlobBytes"`
	SignerSets   []SignerSet    `json:"signerSets"`
	Assets       []Asset        `json:"assets"`
}

// SignerSet holds the keys that sign heights From to To, both inclusive, and how many of them must agree. A nil To
// means the set is still in use.
type SignerSet struct {
	From     uint64   `json:"from"`
	To       *uint64  `json:"to"`
	Required int      `json:"required"`
	Keys     []string `json:"keys"`
}

// Asset is a tracked asset, its ID in the family's canonical form.
type Asset struct {
	ID       string         `json:"id"`
	From     uint64         `json:"from"`
	Settings jsontext.Value `json:"settings"` // checked by the family
}

// Parse reads a trust file. It refuses anything two JSON readers could take differently: repeated or differently cased
// member names, unknown members, trailing data, null, and numbers other than integers from 0 to 2^53-1.
func Parse(data []byte) (File, error) {
	if err := checkTokens(data); err != nil {
		return File{}, err
	}
	var f File
	if err := jsonv2.Unmarshal(data, &f, jsonv2.RejectUnknownMembers(true)); err != nil {
		return File{}, err
	}
	if err := checkFromPresent(data); err != nil {
		return File{}, err
	}
	if f.Version != Version {
		return File{}, fmt.Errorf("%w: %d", ErrVersion, f.Version)
	}
	seen := make(map[string]bool, len(f.Chains))
	for _, c := range f.Chains {
		if seen[c.ID] {
			return File{}, fmt.Errorf("%w: %q", ErrDuplicateChain, c.ID)
		}
		seen[c.ID] = true
		if err := c.Validate(); err != nil {
			return File{}, fmt.Errorf("chain %q: %w", c.ID, err)
		}
	}
	return f, nil
}

func checkTokens(data []byte) error {
	dec := jsontext.NewDecoder(bytes.NewReader(data))
	for {
		tok, err := dec.ReadToken()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		if tok.Kind() == jsontext.KindNull {
			return fmt.Errorf("%w at %s", ErrNull, dec.StackPointer())
		}
		if tok.Kind() == jsontext.KindNumber {
			if n, err := tok.Uint(); err != nil || n > maxSafeInteger {
				return fmt.Errorf("%w at %s: %s", ErrNumber, dec.StackPointer(), tok.String())
			}
		}
	}
}

// checkFromPresent refuses a signer set or asset without from. json/v2 has no required option, and a missing from
// would read as height 0.
func checkFromPresent(data []byte) error {
	var presence struct {
		Chains []struct {
			SignerSets []struct {
				From *uint64 `json:"from"`
			} `json:"signerSets"`
			Assets []struct {
				From *uint64 `json:"from"`
			} `json:"assets"`
		} `json:"chains"`
	}
	if err := jsonv2.Unmarshal(data, &presence); err != nil {
		return err
	}
	for i, c := range presence.Chains {
		for j, s := range c.SignerSets {
			if s.From == nil {
				return fmt.Errorf("chains[%d] signer set %d: %w", i, j, ErrMissingFrom)
			}
		}
		for j, a := range c.Assets {
			if a.From == nil {
				return fmt.Errorf("chains[%d] asset %d: %w", i, j, ErrMissingFrom)
			}
		}
	}
	return nil
}

// Validate checks one chain entry by the rules Parse applies to each: CAIP-2 syntax, a family, a size limit, contiguous
// signer sets with valid keys, and unique asset IDs.
func (c Chain) Validate() error {
	if !caip2.MatchString(c.ID) {
		return ErrChainID
	}
	if c.Family == "" {
		return ErrFamily
	}
	if c.MaxBlobBytes == 0 {
		return ErrMaxBlobBytes
	}
	if len(c.SignerSets) == 0 {
		return ErrSignerSets
	}
	for i, s := range c.SignerSets {
		if err := s.check(); err != nil {
			return fmt.Errorf("signer set %d: %w", i, err)
		}
		if i > 0 {
			if prev := c.SignerSets[i-1]; prev.To == nil || s.From != *prev.To+1 {
				return fmt.Errorf("signer set %d: %w", i, ErrSignerSets)
			}
		}
	}
	ids := make(map[string]bool, len(c.Assets))
	for _, a := range c.Assets {
		if a.ID == "" || ids[a.ID] {
			return fmt.Errorf("%w: %q", ErrAsset, a.ID)
		}
		ids[a.ID] = true
	}
	return nil
}

func (s SignerSet) check() error {
	if s.To != nil && *s.To < s.From {
		return ErrRange
	}
	if s.Required < 1 || s.Required > len(s.Keys) {
		return ErrRequired
	}
	keys := make(map[string]bool, len(s.Keys))
	for _, k := range s.Keys {
		if err := checkKey(k); err != nil {
			return err
		}
		if keys[k] {
			return fmt.Errorf("%w: %s", ErrDuplicateKey, k)
		}
		keys[k] = true
	}
	return nil
}

func checkKey(key string) error {
	b, err := hex.DecodeString(key)
	if err != nil || len(b) != secp256k1.PubKeyBytesLenCompressed || hex.EncodeToString(b) != key {
		return fmt.Errorf("%w: %q", ErrKey, key)
	}
	if _, err := secp256k1.ParsePubKey(b); err != nil {
		return fmt.Errorf("%w: %w", ErrKey, err)
	}
	return nil
}
