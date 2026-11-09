package trust

import (
	"encoding/hex"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

const (
	keyA = "02a4fac163f4665d299c763e163afc5188a8523a7450fbe4432175fafbce630d79"
	keyB = "029cafb7f8ec26a8d4602ededcce20e55d85c2ff26923cbf96cfc2528459cc2adb"
)

const testFile = `{
  "version": 1,
  "chains": [
    { "chain": "eip155:1", "family": "evm", "maxBlobBytes": 4000000,
      "signerSets": [
        { "from": 100, "to": 199, "required": 2, "keys": ["` + keyA + `", "` + keyB + `"] },
        { "from": 200, "required": 1, "keys": ["` + keyB + `"] } ],
      "assets": [ { "id": "8d0d000ee44948fc98c9b98a4fa4921476f08b0d", "from": 150, "settings": {"supplySlot": "0x35"} } ] },
    { "chain": "eip155:56", "family": "evm", "maxBlobBytes": 5000000,
      "signerSets": [ { "from": 300, "required": 1, "keys": ["` + keyA + `"] } ],
      "assets": [] }
  ]
}`

func TestParse(t *testing.T) {
	t.Parallel()
	to := uint64(199)
	want := File{Version: 1, Chains: []Chain{
		{
			ID: "eip155:1", Family: "evm", MaxBlobBytes: 4000000,
			SignerSets: []SignerSet{
				{From: 100, To: &to, Required: 2, Keys: []string{keyA, keyB}},
				{From: 200, Required: 1, Keys: []string{keyB}},
			},
			Assets: []Asset{{ID: "8d0d000ee44948fc98c9b98a4fa4921476f08b0d", From: 150, Settings: jsontext.Value(`{"supplySlot": "0x35"}`)}},
		},
		{
			ID: "eip155:56", Family: "evm", MaxBlobBytes: 5000000,
			SignerSets: []SignerSet{{From: 300, Required: 1, Keys: []string{keyA}}},
			Assets:     []Asset{},
		},
	}}
	got, err := Parse([]byte(testFile))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Parse =\n%+v\nwant\n%+v", got, want)
	}
}

// errSyntax stands for any *jsontext.SyntacticError, which has no sentinel.
var errSyntax = errors.New("syntax error")

func TestParseRejects(t *testing.T) {
	t.Parallel()
	a, err := hex.DecodeString(keyA)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := secp256k1.ParsePubKey(a)
	if err != nil {
		t.Fatal(err)
	}
	uncompressed := hex.EncodeToString(pub.SerializeUncompressed())
	setA := `"keys": ["` + keyA + `"] } ]`
	cases := []struct {
		name     string
		from, to string
		wantErr  error
	}{
		{"repeated member", `"required": 2,`, `"required": 2, "required": 1,`, jsontext.ErrDuplicateName},
		{"member in another case", `"required": 2,`, `"Required": 2,`, jsonv2.ErrUnknownName},
		{"unknown member", `"from": 300,`, `"from": 300, "note": "x",`, jsonv2.ErrUnknownName},
		{"trailing value", "\n}", "\n} {}", errSyntax},
		{"invalid UTF-8", `"family": "evm", "maxBlobBytes": 5000000`, "\"family\": \"ev\xffm\", \"maxBlobBytes\": 5000000", errSyntax},
		{"null", `"to": 199`, `"to": null`, ErrNull},
		{"integer above 2^53-1", `"maxBlobBytes": 4000000`, `"maxBlobBytes": 9007199254740992`, ErrNumber},
		{"negative number", `"required": 2,`, `"required": -1,`, ErrNumber},
		{"signer set without from", `{ "from": 300, `, `{ `, ErrMissingFrom},
		{"asset without from", `"from": 150, `, ``, ErrMissingFrom},
		{"another version", `"version": 1`, `"version": 2`, ErrVersion},
		{"not CAIP-2", `"eip155:1"`, `"eip155"`, ErrChainID},
		{"chain listed twice", `"eip155:56"`, `"eip155:1"`, ErrDuplicateChain},
		{"no family", `"family": "evm", "maxBlobBytes": 5000000`, `"family": "", "maxBlobBytes": 5000000`, ErrFamily},
		{"maxBlobBytes 0", `"maxBlobBytes": 4000000`, `"maxBlobBytes": 0`, ErrMaxBlobBytes},
		{"no signer sets", `"signerSets": [ { "from": 300, "required": 1, ` + setA, `"signerSets": []`, ErrSignerSets},
		{"gap between sets", `{ "from": 200,`, `{ "from": 201,`, ErrSignerSets},
		{"overlapping sets", `{ "from": 200,`, `{ "from": 199,`, ErrSignerSets},
		{"set after an open set", setA, `"keys": ["` + keyA + `"] }, { "from": 400, "required": 1, ` + setA, ErrSignerSets},
		{"set ends before it starts", `"to": 199`, `"to": 99`, ErrRange},
		{"required 0", `"required": 2,`, `"required": 0,`, ErrRequired},
		{"required above the keys", `"required": 2,`, `"required": 3,`, ErrRequired},
		{"upper-case key", `"` + keyA + `", "` + keyB, `"` + strings.ToUpper(keyA) + `", "` + keyB, ErrKey},
		{"uncompressed key", `"` + keyA + `", "` + keyB, `"` + uncompressed + `", "` + keyB, ErrKey},
		{"key not on the curve", `"` + keyA + `", "` + keyB, `"02` + strings.Repeat("ff", 32) + `", "` + keyB, ErrKey},
		{"key twice in a set", `"` + keyA + `", "` + keyB, `"` + keyA + `", "` + keyA, ErrDuplicateKey},
		{"empty asset id", `"id": "8d0d000ee44948fc98c9b98a4fa4921476f08b0d"`, `"id": ""`, ErrAsset},
		{"asset listed twice", `"assets": []`, `"assets": [ { "id": "x", "from": 1 }, { "id": "x", "from": 2 } ]`, ErrAsset},
	}
	for _, tc := range cases {
		if n := strings.Count(testFile, tc.from); n != 1 {
			t.Fatalf("%s: %q occurs %d times", tc.name, tc.from, n)
		}
		_, err := Parse([]byte(strings.Replace(testFile, tc.from, tc.to, 1)))
		matched := errors.Is(err, tc.wantErr)
		if errors.Is(tc.wantErr, errSyntax) {
			var syntax *jsontext.SyntacticError
			matched = errors.As(err, &syntax)
		}
		if !matched {
			t.Errorf("%s: Parse = %v, want %v", tc.name, err, tc.wantErr)
		}
	}
}
