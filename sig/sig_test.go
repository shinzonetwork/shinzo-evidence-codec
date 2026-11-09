package sig

import (
	"encoding/hex"
	"errors"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// Signed with defradb's crypto.Sign at 2a899b860df3. The private keys are SHA-256("signer") and
// SHA-256("other signer").
const (
	statement   = "statement"
	signer      = "02a4fac163f4665d299c763e163afc5188a8523a7450fbe4432175fafbce630d79"
	otherSigner = "029cafb7f8ec26a8d4602ededcce20e55d85c2ff26923cbf96cfc2528459cc2adb"
	signature   = "3045022100cacba320fb8603f3fdf39ba099772aabbb7da09c91ee0504e87d6bc3734806dd" +
		"02201268962b0599eed89661c107d1646bb058125886ad28a8f0ad5160e2178b2a50"
)

func TestVerifyStatement(t *testing.T) {
	t.Parallel()
	if err := VerifyStatement([]byte(statement), signer, TypeES256K, signature); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyStatementRejects(t *testing.T) {
	t.Parallel()
	compressed, err := hex.DecodeString(signer)
	if err != nil {
		t.Fatal(err)
	}
	key, err := secp256k1.ParsePubKey(compressed)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name      string
		statement string
		signer    string
		typ       string
		signature string
		wantErr   error
	}{
		{"another statement", "other statement", signer, TypeES256K, signature, ErrInvalid},
		{"another signer", statement, otherSigner, TypeES256K, signature, ErrInvalid},
		{"uncompressed signer", statement, hex.EncodeToString(key.SerializeUncompressed()), TypeES256K, signature, ErrSigner},
		{
			"R and S without DER", statement, signer, TypeES256K,
			"cacba320fb8603f3fdf39ba099772aabbb7da09c91ee0504e87d6bc3734806dd" +
				"1268962b0599eed89661c107d1646bb058125886ad28a8f0ad5160e2178b2a50",
			ErrInvalid,
		},
		{"unsupported type", statement, signer, "EdDSA", signature, ErrUnsupportedType},
	}
	for _, tc := range cases {
		if err := VerifyStatement([]byte(tc.statement), tc.signer, tc.typ, tc.signature); !errors.Is(err, tc.wantErr) {
			t.Errorf("%s: VerifyStatement = %v, want %v", tc.name, err, tc.wantErr)
		}
	}
}
